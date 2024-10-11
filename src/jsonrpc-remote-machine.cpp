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

#include <algorithm>
#include <array>
#include <cstdio>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <stdexcept>
#include <memory>
#include <iostream>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <system_error>

#include <fcntl.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "asio-config.h" // must be included before any ASIO header
#include <boost/asio/signal_set.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#pragma GCC diagnostic pop

#include "base64.h"
#include "json-util.h"
#include "jsonrpc-discover.h"
#include "machine.h"
#include "unique-c-ptr.h"

#define SLOG_PREFIX log_prefix
#include "slog.h"

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define PROGRAM_NAME "jsonrpc-remote-cartesi-machine"

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace asio = boost::asio;   // from <boost/asio.hpp>
using tcp = asio::ip::tcp;      // from <boost/asio/ip/tcp.hpp>

/// \brief Type for printing time, log severity level, program name, pid, and ppid prefix to each log line
struct log_prefix {
    slog::severity_level level;
};

/// \brief Stream-out operator for log prefix class
std::ostream &operator<<(std::ostream &out, log_prefix prefix) {
    using namespace slog;
    char stime[std::size("yyyy-mm-dd hh-mm-ss")];
    const time_t t = time(nullptr);
    struct tm ttime {};
    if (strftime(std::data(stime), std::size(stime), "%Y-%m-%d %H-%M-%S", localtime_r(&t, &ttime))) {
        out << stime << " ";
    }
    out << to_string(prefix.level) << " ";
    out << PROGRAM_NAME << " ";
    out << "pid:" << getpid() << " ";
    out << "ppid:" << getppid() << " ";
    out << "pgid:" << getpgid(0) << " ";
    return out;
}

using namespace std::string_literals;
using json = nlohmann::json;

/// \brief Server semantic version major
static constexpr uint32_t server_version_major = 0;
/// \brief Server semantic version minor
static constexpr uint32_t server_version_minor = 5;
/// \brief Server semantic version patch
static constexpr uint32_t server_version_patch = 0;
/// \brief Server semantic version pre_release
static constexpr const char *server_version_pre_release = "";
/// \brief Server semantic version build
static constexpr const char *server_version_build = "";

/// \brief Installs a signal handler
template <typename HANDLER>
static void install_signal_handler(int signum, HANDLER handler) {
    struct sigaction act {};
    if (sigemptyset(&act.sa_mask) < 0) {
        throw std::system_error{errno, std::generic_category(), "sigemptyset failed"};
    }
    act.sa_handler = handler; // NOLINT(cppcoreguidelines-pro-type-union-access)
    act.sa_flags = SA_RESTART;
    if (sigaction(signum, &act, nullptr) < 0) {
        throw std::system_error{errno, std::generic_category(), "sigaction failed"};
    }
}

/// \brief Installs signal handlers that should not stop read()/write() primitives.
static void install_restart_signal_handlers(void) {
    // Prevent dead children from becoming zombies
    install_signal_handler(SIGCHLD, SIG_IGN);
    // Prevent this process from suspending after issuing a SIGTTOU when trying
    // to configure terminal (on htif::init_console())
    // https://pubs.opengroup.org/onlinepubs/009604599/basedefs/xbd_chap11.html#tag_11_01_04
    // https://pubs.opengroup.org/onlinepubs/009604499/functions/tcsetattr.html
    // http://curiousthing.org/sigttin-sigttou-deep-dive-linux
    install_signal_handler(SIGTTOU, SIG_IGN);
    // Prevent this process from crashing on SIGPIPE when remote connection is closed
    install_signal_handler(SIGPIPE, SIG_IGN);
}

//------------------------------------------------------------------------------

struct http_handler;
struct http_session;
template <typename HTTP_REQ>
static http::message_generator handle_request(HTTP_REQ &&rreq, const std::shared_ptr<http_session> &session);

// Handles a HTTP session
struct http_session : std::enable_shared_from_this<http_session> {
    beast::tcp_stream stream;
    beast::flat_buffer buffer;
    std::unique_ptr<http::request_parser<http::string_body>> req_parser;
    std::shared_ptr<http_handler> handler;

    // Take ownership of the stream
    http_session(tcp::socket &&socket, std::shared_ptr<http_handler> handler) :
        stream(std::move(socket)),
        handler(std::move(handler)) {}

    // Begins an asynchronous read for the entire HTTP request
    void do_read_request() {
        // Create a new request parser
        req_parser = std::make_unique<http::request_parser<http::string_body>>();
        req_parser->eager(true);
        req_parser->body_limit(16777216U); // can receive up to 16MB

        // Read a request
        http::async_read(stream, buffer, *req_parser,
            beast::bind_front_handler(&http_session::on_read_request, shared_from_this()));
    }

    // Receives a complete HTTP request
    void on_read_request(beast::error_code ec, std::size_t bytes_transferred) {
        (void) bytes_transferred;

        // Take ownership of request parser, so it can be freed on this scope termination
        auto parser = std::move(req_parser);

        // Check error code
        if (ec == asio::error::operation_aborted) { // Operation may be aborted
            return;
        } else if (ec == http::error::end_of_stream) { // This means the connection was closed by the client
            shutdown_send();
            return;
        } else if (ec) { // Unexpected error
            SLOG(error) << "read request error:" << ec.what();
            return;
        }

        // Retrieve the request
        auto req = parser->release();

        // Process the request
        auto res = handle_request(std::move(req), shared_from_this());

        // The stream may be closed during fork() requests, in that case we have nothing to reply
        if (!stream.socket().is_open()) {
            return;
        }

        // Send the response
        send_response(std::move(res));
    }

    // Sends a HTTP response
    void send_response(http::message_generator &&msg) {
        const bool keep_alive = msg.keep_alive();

        // Write the response
        beast::async_write(stream, std::move(msg),
            beast::bind_front_handler(&http_session::on_send_response, shared_from_this(), keep_alive));
    }

    // Called when HTTP response is fully sent
    void on_send_response(bool keep_alive, beast::error_code ec, std::size_t bytes_transferred) {
        (void) bytes_transferred;

        // Check error code
        if (ec == asio::error::operation_aborted) { // Operation may be aborted
            return;
        } else if (ec) { // Unexpected error
            SLOG(error) << "send response error:" << ec.what();
            shutdown_send();
            return;
        }

        if (keep_alive) {
            // Read next request for this session
            do_read_request();
        } else {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            shutdown_send();
        }
    }

    // Called we are done with this HTTP session
    void shutdown_send() {
        // Here, we deliberately shutdowns only the outgoing traffic,
        // so the server does not becomes full of TCP connections in TIME_WAIT state.

        // Send a TCP send shutdown.
        beast::error_code ec;
        (void) stream.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }

    // Called by HTTP handler to cancel asynchronous operations and close the session
    void close() {
        beast::error_code ec;
        (void) stream.socket().cancel(ec);
        (void) stream.socket().close(ec);
    }
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches HTTP sessions
struct http_handler : std::enable_shared_from_this<http_handler> {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    asio::io_context &ioc;                             ///< IO context
    asio::signal_set signals;                          ///< Signal set used for process termination notifications
    tcp::endpoint local_endpoint;                      ///< Address server receives requests at
    tcp::acceptor acceptor;                            ///< TCP connection acceptor
    std::unique_ptr<cartesi::machine> machine;         ///< Cartesi Machine, if any
    std::vector<std::weak_ptr<http_session>> sessions; ///< HTTP sessions

    http_handler(asio::io_context &ioc, tcp::acceptor &&acceptor) :
        ioc(ioc),
        signals(ioc),
        local_endpoint(acceptor.local_endpoint()),
        acceptor(std::move(acceptor)) {
        SLOG(info) << "remote machine server bound to " << local_endpoint;
    }

    // Installs all handlers that should stop the HTTP server
    void install_termination_signal_handlers() {
        signals.add(SIGINT);
        signals.add(SIGTERM);
        signals.add(SIGBUS);
        signals.async_wait(beast::bind_front_handler(&http_handler::on_signal, shared_from_this()));
    }

    // Begins an asynchronous accept
    void next_accept() {
        acceptor.async_accept(ioc, beast::bind_front_handler(&http_handler::on_accept, shared_from_this()));
    }

    // Bind the HTTP server to a new TCP port
    void rebind(tcp::acceptor &&new_acceptor) {
        // Stop asynchronous accept and close the acceptor
        beast::error_code ec;
        (void) acceptor.cancel(ec);
        (void) acceptor.close(ec);
        // Replace current acceptor with the new one
        acceptor = std::move(new_acceptor);
        local_endpoint = acceptor.local_endpoint();
        next_accept();
    }

    // Stop accepting new connections
    void stop() {
        beast::error_code ec;
        (void) acceptor.close(ec);
        (void) acceptor.cancel(ec);
        (void) signals.cancel(ec);
        (void) signals.clear(ec);
    }

    // Close open sessions
    void close_sessions() {
        for (const auto &weak_session : sessions) {
            auto session = weak_session.lock();
            if (session) {
                session->close();
            }
        }
    }

private:
    // Receives a termination signal
    void on_signal(const beast::error_code &ec, int signum) {
        // Operation may be aborted (e.g stop() was called)
        if (ec == asio::error::operation_aborted) {
            return;
        }
        SLOG(info) << local_endpoint << " http handler terminated due to signal " << signum;
        stop();
    }

    // Receives an incoming TCP connection
    void on_accept(const beast::error_code ec, tcp::socket socket) {
        // Operation may be aborted (e.g rebind() or stop() was called)
        if (ec == asio::error::operation_aborted) {
            return;
        } else if (ec) {
            SLOG(error) << local_endpoint << " accept error: " << ec.what();
            return;
        }

        // Disable Nagle's algorithm to minimize TCP connection latency
        const boost::asio::ip::tcp::no_delay no_delay_option(true);
        socket.set_option(no_delay_option);

        // Create the session
        auto session = std::make_shared<http_session>(std::move(socket), shared_from_this());

        // Remove previous expired sessions
        sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                           [](const std::weak_ptr<http_session> &weak_session) { return weak_session.expired(); }),
            sessions.end());

        // Keep track of the new session
        sessions.push_back(session);

        // Run the session
        session->do_read_request();

        // Accept next connection
        next_accept();
    }
};

//------------------------------------------------------------------------------

/// \brief Names for JSONRPC error codes
enum jsonrpc_error_code : int {
    parse_error = -32700,      ///< When the request failed to parse
    invalid_request = -32600,  ///< When the request was invalid (missing fields, wrong types etc)
    method_not_found = -32601, ///< When the method was not found
    invalid_params = -32602,   ///< When the parameters provided don't meet the method's needs
    internal_error = -32603,   ///< When there was an internal error (runtime etc)
    server_error = -32000      ///< When there was some problem with the server itself
};

/// \brief Returns a successful JSONRPC response as a JSON object
/// \param j JSON request, from which an id is obtained
/// \param result Result to send in response (defaults to true)
/// \returns JSON object with response
static json jsonrpc_response_ok(const json &j, const json &result = true) {
    return {{"jsonrpc", "2.0"}, {"id", j.contains("id") ? j["id"] : json{nullptr}}, {"result", result}};
}

/// \brief Returns a failed JSONRPC response as a JSON object
/// \param j JSON request, from which an id is obtained
/// \param code JSONRPC Error code
/// \param message Error message
/// \returns JSON object with response
static json jsonrpc_response_error(const json &j, jsonrpc_error_code code, const std::string &message) {
    return {{"jsonrpc", "2.0"}, {"id", j.contains("id") ? j["id"] : json{nullptr}},
        {"error", {{"code", code}, {"message", message}}}};
}

/// \brief Returns a parse error JSONRPC response as a JSON object
/// \param message Error message
/// \returns JSON object with response
static json jsonrpc_response_parse_error(const std::string &message) {
    return jsonrpc_response_error(nullptr, jsonrpc_error_code::parse_error, message);
}

/// \brief Returns an invalid request JSONRPC response as a JSON object
/// \param j JSON request, from which an id is obtained
/// \param message Error message
/// \returns JSON object with response
static json jsonrpc_response_invalid_request(const json &j, const std::string &message) {
    return jsonrpc_response_error(j, jsonrpc_error_code::invalid_request, message);
}

/// \brief Returns an internal error JSONRPC response as a JSON object
/// \param j JSON request, from which an id is obtained
/// \param message Error message
/// \returns JSON object with response
static json jsonrpc_response_internal_error(const json &j, const std::string &message) {
    return jsonrpc_response_error(j, jsonrpc_error_code::internal_error, message);
}

/// \brief Returns a server error JSONRPC response as a JSON object
/// \param j JSON request, from which an id is obtained
/// \param message Error message
/// \returns JSON object with response
static json jsonrpc_response_server_error(const json &j, const std::string &message) {
    return jsonrpc_response_error(j, jsonrpc_error_code::server_error, message);
}

/// \brief Returns a method not found JSONRPC response as a JSON object
/// \param j JSON request, from which an id is obtained
/// \param message Error message
/// \returns JSON object with response
static json jsonrpc_response_method_not_found(const json &j, const std::string &message) {
    return jsonrpc_response_error(j, jsonrpc_error_code::method_not_found, message);
}

/// \brief Returns a invalid params JSONRPC response as a JSON object
/// \param j JSON request, from which an id is obtained
/// \param message Error message
/// \returns JSON object with response
static json jsonrpc_response_invalid_params(const json &j, const std::string &message) {
    return jsonrpc_response_error(j, jsonrpc_error_code::invalid_params, message);
}

/// \brief Checks that a JSON object contains only fields with allowed keys
/// \param j JSON object to test
/// \param keys Set of allowed keys
static void jsonrpc_check_allowed_fields(const json &j, const std::unordered_set<std::string> &keys,
    const std::string &base = "params/") {
    for (const auto &[key, val] : j.items()) {
        if (keys.find(key) == keys.end()) {
            // NOLINTNEXTLINE(performance-inefficient-string-concatenation)
            throw std::invalid_argument("unexpected field \"/"s + base + key + "\""s);
        }
    }
}

/// \brief Checks that a JSON object all fields with given keys
/// \param j JSON object to test
/// \param keys Set of mandatory keys
static void jsonrpc_check_mandatory_fields(const json &j, const std::unordered_set<std::string> &keys,
    const std::string &base = "params/") {
    for (const auto &key : keys) {
        if (!j.contains(key)) {
            // NOLINTNEXTLINE(performance-inefficient-string-concatenation)
            throw std::invalid_argument("missing field \"/"s + base + key + "\""s);
        }
    }
}

/// \brief Checks that a JSON object contains no fields
/// \param j JSON object to test
static void jsonrpc_check_no_params(const json &j) {
    if (j.contains("params") && !j["params"].empty()) {
        throw std::invalid_argument("unexpected \"params\" field");
    }
}

/// \brief Type trait to test if a type has been encapsulated in an optional_param
/// \tparam T type to test
/// \details This is the default case
template <typename T>
struct is_optional_param : std::false_type {};

/// \brief Type trait to test if a type has been encapsulated in an optional_param
/// \tparam T type to test
/// \details This is the encapsulated case
template <typename T>
struct is_optional_param<cartesi::optional_param<T>> : std::true_type {};

/// \brief Shortcut to the type trait to test if a type has been encapsulated in an optional_param
/// \tparam T type to test
template <typename T>
inline constexpr bool is_optional_param_v = is_optional_param<T>::value;

/// \brief Counts the number of parameters that are mandatory (i.e., not wrapped in optional_param)
/// \tparam ARGS Parameter pack to test
/// \returns Number of parameters wrapped in optional_param
template <typename... ARGS>
constexpr size_t count_mandatory_params(void) {
    return ((is_optional_param_v<ARGS> ? 0 : 1) + ... + 0);
}

/// \brief Returns index of the first parameter that is optional (i.e., wrapped in optional_param)
/// \tparam ARGS Parameter pack to test
/// \tparam I Parameter pack with indices of each parameter
/// \returns Index of first parameter that is optional
template <typename... ARGS, size_t... I>
size_t first_optional_param(const std::tuple<ARGS...> &, std::index_sequence<I...>) {
    if constexpr (sizeof...(ARGS) > 0) {
        return std::min({(is_optional_param_v<ARGS> ? I + 1 : sizeof...(ARGS) + 1)...});
    } else {
        return sizeof...(ARGS) + 1;
    }
}

/// \brief Returns index of the first parameter that is optional (i.e., wrapped in optional_param)
/// \tparam ARGS Parameter pack to test
/// \tparam I Parameter pack with indices of each parameter
/// \returns Index of first parameter that is optional
template <typename... ARGS, size_t... I>
size_t last_mandatory_param(const std::tuple<ARGS...> &, std::index_sequence<I...>) {
    if constexpr (sizeof...(ARGS) > 0) {
        return std::max({(!is_optional_param_v<ARGS> ? I + 1 : 0)...});
    } else {
        return 0;
    }
}

/// \brief Checks if an argument has a value
/// \tparam T Type of argument
/// \param t Argument
/// \returns True if it has a value
/// \details This is the default overload
template <typename T>
bool has_arg(const T &t) {
    (void) t;
    return true;
}

/// \brief Checks if an argument has a value
/// \tparam T Type of argument
/// \param t Argument
/// \returns True if it has a value
/// \details This is the overload for optional parameters (i.e., wrapped in optional_param)
template <typename T>
bool has_arg(const cartesi::optional_param<T> &t) {
    return t.has_value();
}

/// \brief Finds the index of the first missing optional argument (i.e., wrapped in optional_param)
/// \tparam ARGS Parameter pack with parameter types
/// \tparam I Parameter pack with indices of each parameter
/// \returns Index of first optional argument that is missing
/// \details The function returns the index + 1, so that sizeof...(ARGS)+1 means no missing optional arguments
template <typename... ARGS, size_t... I>
size_t first_missing_optional_arg(const std::tuple<ARGS...> &tup, std::index_sequence<I...>) {
    if constexpr (sizeof...(ARGS) > 0) {
        return std::min({(!has_arg(std::get<I>(tup)) ? I + 1 : sizeof...(ARGS) + 1)...});
    } else {
        return 1;
    }
}

/// \brief Finds the index of the last argument that is present
/// \tparam ARGS Parameter pack with parameter types
/// \tparam I Parameter pack with indices of each parameter
/// \returns Index of last argument that is present
/// \details The function returns the index + 1, so that 0 means no arguments are present
template <typename... ARGS, size_t... I>
size_t last_present_arg(const std::tuple<ARGS...> &tup, std::index_sequence<I...>) {
    if constexpr (sizeof...(ARGS) > 0) {
        return std::max({(has_arg(std::get<I>(tup)) ? I + 1 : 0)...});
    } else {
        return 0;
    }
}

/// \brief Counts the number of arguments provided
/// \tparam ARGS Parameter pack with parameter types
/// \tparam I Parameter pack with indices of each parameter
/// \param tup Tuple with all arguments
/// \param i Index sequence
/// \returns Number of arguments provided
template <typename... ARGS, size_t... I>
size_t count_args(const std::tuple<ARGS...> &tup, const std::index_sequence<I...> &i) {
    // check first optional parameter happens after last mandatory parameter
    auto fop = first_optional_param(tup, i);
    auto lmp = last_mandatory_param(tup, i);
    if (fop <= lmp) {
        throw std::invalid_argument{"first optional parameter must come after last mandatory parameter"};
    }
    // make sure last present optional argument comes before first missing optional argument
    auto fmoa = first_missing_optional_arg(tup, i);
    auto lpa = last_present_arg(tup, i);
    if (lpa >= fmoa) {
        throw std::invalid_argument{"first missing optional argument must come after last present argument"};
    }
    return std::max(lmp, lpa);
}

/// \brief Counts the number of arguments provided
/// \tparam ARGS Parameter pack with parameter types
/// \param tup Tuple with all arguments
/// \returns Number of arguments provided
template <typename... ARGS>
size_t count_args(const std::tuple<ARGS...> &tup) {
    return count_args(tup, std::make_index_sequence<sizeof...(ARGS)>{});
}

/// \brief Parse arguments from an array
/// \tparam ARGS Parameter pack with parameter types
/// \tparam I Parameter pack with indices of each parameter
/// \param j JSONRPC request params
/// \returns tuple with arguments
template <typename... ARGS, size_t... I>
std::tuple<ARGS...> parse_array_args(const json &j, std::index_sequence<I...>) {
    std::tuple<ARGS...> tp;
    (cartesi::ju_get_field(j, static_cast<uint64_t>(I), std::get<I>(tp)), ...);
    return tp;
}

/// \brief Parse arguments from an array
/// \tparam ARGS Parameter pack with parameter types
/// \param j JSONRPC request params
/// \returns tuple with arguments
template <typename... ARGS>
std::tuple<ARGS...> parse_array_args(const json &j) {
    return parse_array_args<ARGS...>(j, std::make_index_sequence<sizeof...(ARGS)>{});
}

/// \brief Parse arguments from an object
/// \tparam ARGS Parameter pack with parameter types
/// \tparam I Parameter pack with indices of each parameter
/// \param j JSONRPC request params
/// \param param_name Name of each parameter
/// \returns tuple with arguments
template <typename... ARGS, size_t... I>
std::tuple<ARGS...> parse_object_args(const json &j, const char *(&param_name)[sizeof...(ARGS)],
    std::index_sequence<I...>) {
    std::tuple<ARGS...> tp;
    (cartesi::ju_get_field(j, std::string(param_name[I]), std::get<I>(tp)), ...);
    return tp;
}

/// \brief Parse arguments from an object
/// \tparam ARGS Parameter pack with parameter types
/// \param j JSONRPC request params
/// \param param_name Name of each parameter
/// \returns tuple with arguments
template <typename... ARGS>
std::tuple<ARGS...> parse_object_args(const json &j, const char *(&param_name)[sizeof...(ARGS)]) {
    return parse_object_args<ARGS...>(j, param_name, std::make_index_sequence<sizeof...(ARGS)>{});
}

/// \brief Parse arguments from an object or array
/// \tparam ARGS Parameter pack with parameter types
/// \param j JSONRPC request params
/// \param param_name Name of each parameter
/// \returns tuple with arguments
template <typename... ARGS>
std::tuple<ARGS...> parse_args(const json &j, const char *(&param_name)[sizeof...(ARGS)]) {
    constexpr auto mandatory_params = count_mandatory_params<ARGS...>();
    if (!j.contains("params")) {
        if constexpr (mandatory_params == 0) {
            return std::make_tuple(ARGS{}...);
        }
        throw std::invalid_argument("missing field \"params\"");
    }
    const json &params = j["params"];
    if (!params.is_object() && !params.is_array()) {
        throw std::invalid_argument("\"params\" field not object or array");
    }
    if (params.is_object()) {
        //??D This could be optimized so we don't construct these sets every call
        jsonrpc_check_mandatory_fields(params,
            std::unordered_set<std::string>{param_name, param_name + mandatory_params});
        jsonrpc_check_allowed_fields(params, std::unordered_set<std::string>{param_name, param_name + sizeof...(ARGS)});
        return parse_object_args<ARGS...>(params, param_name);
    }
    if (params.size() < mandatory_params) {
        throw std::invalid_argument("not enough entries in \"params\" array");
    }
    if (params.size() > sizeof...(ARGS)) {
        throw std::invalid_argument("too many entries in \"params\" array");
    }
    return parse_array_args<ARGS...>(params);
}

/// \brief JSONRPC handler for the shutdown method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_shutdown_handler(const json &j, const std::shared_ptr<http_session> &session) {
    jsonrpc_check_no_params(j);
    // Close acceptor right-away so the port can be immediately reused after request response.
    // This will also stop the IO main loop when all connections are closed,
    // because the IO context will run out of pending events to execute.
    session->handler->stop();
    SLOG(trace) << session->handler->local_endpoint << " shutting down";
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for rpc.discover method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
/// \details This RPC allows a client to download the entire schema of the service
static json jsonrpc_rpc_discover_handler(const json &j, const std::shared_ptr<http_session> &session) {
    (void) session;
    const static json schema = json::parse(cartesi::jsonrpc_discover_json);
    return jsonrpc_response_ok(j, schema);
}

/// \brief JSONRPC handler for the get_version method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_get_version_handler(const json &j, const std::shared_ptr<http_session> &session) {
    (void) session;
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j,
        {
            {"major", server_version_major},
            {"minor", server_version_minor},
            {"patch", server_version_patch},
            {"pre_release", server_version_pre_release},
            {"build", server_version_build},
        });
}

/// \brief Parse a address from a string to an endpoint.
/// \param address Address string (e.g "127.0.0.1:8000")
/// \returns Endpoint address
static tcp::endpoint address_to_endpoint(const std::string &address) {
    try {
        const auto pos = address.find_last_of(':');
        const std::string ip = address.substr(0, pos);
        const int port = std::stoi(address.substr(pos + 1));
        if (port < 0 || port > 65535) {
            throw std::runtime_error{"invalid port"};
        }
        return {asio::ip::make_address(ip), static_cast<uint16_t>(port)};
    } catch (std::exception &e) {
        throw std::runtime_error{"invalid endpoint address \"" + address + "\""};
    }
}

static std::string endpoint_to_string(const tcp::endpoint &endpoint) {
    std::ostringstream ss;
    ss << endpoint;
    return ss.str();
}

/// \brief JSONRPC handler for the fork method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
/// \details Here we allocate a new server that will be used by the child, then we fork.
/// The child will later destroy the old server it inherited from the parent and replace it with the new one.
/// The parent reports the address of the new server back to the client, and destroys its copy of the child's new
/// server. The parent goes on to continue serving from the old server. The child goes on to start serving from the new
/// server.
static json jsonrpc_fork_handler(const json &j, const std::shared_ptr<http_session> &session) {
    jsonrpc_check_no_params(j);
    // Listen in desired port before fork so failures happen still in parent,
    // who can directly report them to client
    tcp::acceptor acceptor{session->handler->ioc, tcp::endpoint{session->handler->local_endpoint.address(), 0}};
    const std::string new_server_address = endpoint_to_string(acceptor.local_endpoint());
    // Notify ASIO that we are about to fork
    session->handler->ioc.notify_fork(asio::io_context::fork_prepare);
    // Done initializing, so we fork
    const int pid = fork();
    if (pid == 0) { // child
        // Notify to ASIO that we are the child
        session->handler->ioc.notify_fork(asio::io_context::fork_child);
        // Close all sessions that were initiated by the parent
        session->handler->close_sessions();
        // Swap current handler acceptor with the new one
        session->handler->rebind(std::move(acceptor));
        SLOG(trace) << session->handler->local_endpoint << " fork child";
    } else if (pid > 0) { // parent and fork() succeeded
        // Notify to ASIO that we are the parent
        session->handler->ioc.notify_fork(asio::io_context::fork_parent);
        // Note that the parent doesn't need the server that will be used by the child,
        // we can close it.
        beast::error_code ec;
        (void) acceptor.close(ec);
        SLOG(trace) << session->handler->local_endpoint << " fork parent";
    } else { // parent and fork() failed
        const int errno_copy = errno;
        SLOG(error) << session->handler->local_endpoint << " fork failed (" << strerror(errno_copy) << ")";
        return jsonrpc_response_server_error(j, "fork failed ("s + strerror(errno_copy) + ")"s);
    }
    const cartesi::fork_result result{new_server_address, static_cast<uint32_t>(pid)};
    return jsonrpc_response_ok(j, result);
}

/// \brief JSONRPC handler for the rebind method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
/// \details Changes the address the server is listening to.
/// After this call, all new connections should be established using the new server address.
static json jsonrpc_rebind_handler(const json &j, const std::shared_ptr<http_session> &session) {
    static const char *param_name[] = {"address"};
    auto args = parse_args<std::string>(j, param_name);
    const std::string new_server_address = std::get<0>(args);
    const tcp::endpoint new_local_endpoint = address_to_endpoint(new_server_address);
    if (new_local_endpoint != session->handler->local_endpoint) {
        SLOG(trace) << session->handler->local_endpoint << " rebinding to " << new_local_endpoint;
        session->handler->rebind(tcp::acceptor{session->handler->ioc, new_local_endpoint});
        SLOG(trace) << session->handler->local_endpoint << " rebound to " << session->handler->local_endpoint;
    } else {
        SLOG(trace) << session->handler->local_endpoint << " rebind skipped";
    }
    const std::string result = endpoint_to_string(session->handler->local_endpoint);
    return jsonrpc_response_ok(j, result);
}

/// \brief JSONRPC handler for the machine.machine.directory method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_machine_directory_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "machine exists");
    }
    static const char *param_name[] = {"directory", "runtime"};
    auto args = parse_args<std::string, cartesi::optional_param<cartesi::machine_runtime_config>>(j, param_name);
    switch (count_args(args)) {
        case 1:
            session->handler->machine = std::make_unique<cartesi::machine>(std::get<0>(args));
            break;
        case 2:
            session->handler->machine = std::make_unique<cartesi::machine>(std::get<0>(args),
                std::get<1>(args).value()); // NOLINT(bugprone-unchecked-optional-access)
            break;
        default:
            throw std::runtime_error{"error detecting number of arguments"};
    }
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.machine.config method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_machine_config_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "machine exists");
    }
    static const char *param_name[] = {"config", "runtime"};
    auto args =
        parse_args<cartesi::machine_config, cartesi::optional_param<cartesi::machine_runtime_config>>(j, param_name);
    switch (count_args(args)) {
        case 1:
            session->handler->machine = std::make_unique<cartesi::machine>(std::get<0>(args));
            break;
        case 2:
            session->handler->machine = std::make_unique<cartesi::machine>(std::get<0>(args),
                std::get<1>(args).value()); // // NOLINT(bugprone-unchecked-optional-access)
            break;
        default:
            throw std::runtime_error{"error detecting number of arguments"};
    }
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.destroy method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_destroy_handler(const json &j, const std::shared_ptr<http_session> &session) {
    jsonrpc_check_no_params(j);
    session->handler->machine.reset();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.store method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_store_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"directory"};
    auto args = parse_args<std::string>(j, param_name);
    session->handler->machine->store(std::get<0>(args));
    return jsonrpc_response_ok(j);
}

/// \brief Translate an interpret_break_reason value to string
/// \param reason interpret_break_reason value to translate
/// \returns String representation of value
static std::string interpreter_break_reason_name(cartesi::interpreter_break_reason reason) {
    using R = cartesi::interpreter_break_reason;
    switch (reason) {
        case R::failed:
            return "failed";
        case R::halted:
            return "halted";
        case R::yielded_manually:
            return "yielded_manually";
        case R::yielded_automatically:
            return "yielded_automatically";
        case R::yielded_softly:
            return "yielded_softly";
        case R::reached_target_mcycle:
            return "reached_target_mcycle";
    }
    throw std::domain_error{"invalid interpreter break reason"};
}

/// \brief JSONRPC handler for the machine.run method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_run_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"mcycle_end"};
    auto args = parse_args<uint64_t>(j, param_name);
    auto reason = session->handler->machine->run(std::get<0>(args));
    return jsonrpc_response_ok(j, interpreter_break_reason_name(reason));
}

/// \brief Translate an uarch_interpret_break_reason value to string
/// \param reason uarch_interpret_break_reason value to translate
/// \returns String representation of value
static std::string uarch_interpreter_break_reason_name(cartesi::uarch_interpreter_break_reason reason) {
    using R = cartesi::uarch_interpreter_break_reason;
    switch (reason) {
        case R::uarch_halted:
            return "uarch_halted";
        case R::reached_target_cycle:
            return "reached_target_cycle";
    }
    throw std::domain_error{"invalid uarch interpreter break reason"};
}

/// \brief JSONRPC handler for the machine.run_uarch method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_run_uarch_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"uarch_cycle_end"};
    auto args = parse_args<uint64_t>(j, param_name);
    auto reason = session->handler->machine->run_uarch(std::get<0>(args));
    return jsonrpc_response_ok(j, uarch_interpreter_break_reason_name(reason));
}

/// \brief JSONRPC handler for the machine.log_step_uarch method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_log_step_uarch_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"log_type"};
    auto args = parse_args<cartesi::not_default_constructible<cartesi::access_log::type>>(j, param_name);
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    return jsonrpc_response_ok(j, session->handler->machine->log_step_uarch(std::get<0>(args).value()));
}

/// \brief JSONRPC handler for the machine.log_step_uarch method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_log_reset_uarch_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"log_type"};
    auto args = parse_args<cartesi::not_default_constructible<cartesi::access_log::type>>(j, param_name);
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    return jsonrpc_response_ok(j, session->handler->machine->log_reset_uarch(std::get<0>(args).value()));
}

/// \brief JSONRPC handler for the machine.verify_step_uarch method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_verify_step_uarch_handler(const json &j, const std::shared_ptr<http_session> &session) {
    (void) session;
    static const char *param_name[] = {"root_hash_before", "log", "root_hash_after"};
    auto args =
        parse_args<cartesi::machine_merkle_tree::hash_type, cartesi::not_default_constructible<cartesi::access_log>,
            cartesi::machine_merkle_tree::hash_type>(j, param_name);
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    cartesi::machine::verify_step_uarch(std::get<0>(args), std::get<1>(args).value(), std::get<2>(args));
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.verify_reset_uarch method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_verify_reset_uarch_handler(const json &j, const std::shared_ptr<http_session> &session) {
    (void) session;
    static const char *param_name[] = {"root_hash_before", "log", "root_hash_after"};
    auto args =
        parse_args<cartesi::machine_merkle_tree::hash_type, cartesi::not_default_constructible<cartesi::access_log>,
            cartesi::machine_merkle_tree::hash_type>(j, param_name);
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    cartesi::machine::verify_reset_uarch(std::get<0>(args), std::get<1>(args).value(), std::get<2>(args));
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.get_proof method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_get_proof_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "log2_size"};
    auto args = parse_args<uint64_t, uint64_t>(j, param_name);
    if (std::get<1>(args) > INT_MAX) {
        throw std::domain_error("log2_size is out of range");
    }
    return jsonrpc_response_ok(j,
        session->handler->machine->get_proof(std::get<0>(args), static_cast<int>(std::get<1>(args))));
}

/// \brief JSONRPC handler for the machine.verify_merkle_tree method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_verify_merkle_tree_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, session->handler->machine->verify_merkle_tree());
}

/// \brief JSONRPC handler for the machine.get_root_hash method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_get_root_hash_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    cartesi::machine_merkle_tree::hash_type hash;
    session->handler->machine->get_root_hash(hash);
    return jsonrpc_response_ok(j, cartesi::encode_base64(hash));
}

/// \brief JSONRPC handler for the machine.read_word method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_read_word_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address"};
    auto args = parse_args<uint64_t>(j, param_name);
    auto address = std::get<0>(args);
    return jsonrpc_response_ok(j, session->handler->machine->read_word(address));
}

/// \brief JSONRPC handler for the machine.read_memory method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_read_memory_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "length"};
    auto args = parse_args<uint64_t, uint64_t>(j, param_name);
    auto address = std::get<0>(args);
    auto length = std::get<1>(args);
    auto data = cartesi::unique_calloc<unsigned char>(length);
    session->handler->machine->read_memory(address, data.get(), length);
    return jsonrpc_response_ok(j, cartesi::encode_base64(data.get(), length));
}

/// \brief JSONRPC handler for the machine.write_memory method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_write_memory_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "data"};
    auto args = parse_args<uint64_t, std::string>(j, param_name);
    auto address = std::get<0>(args);
    auto bin = cartesi::decode_base64(std::get<1>(args));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    session->handler->machine->write_memory(address, reinterpret_cast<unsigned char *>(bin.data()), bin.size());
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_virtual_memory method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_read_virtual_memory_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "length"};
    auto args = parse_args<uint64_t, uint64_t>(j, param_name);
    auto address = std::get<0>(args);
    auto length = std::get<1>(args);
    auto data = cartesi::unique_calloc<unsigned char>(length);
    session->handler->machine->read_virtual_memory(address, data.get(), length);
    return jsonrpc_response_ok(j, cartesi::encode_base64(data.get(), length));
}

/// \brief JSONRPC handler for the machine.write_virtual_memory method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_write_virtual_memory_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "data"};
    auto args = parse_args<uint64_t, std::string>(j, param_name);
    auto address = std::get<0>(args);
    auto bin = cartesi::decode_base64(std::get<1>(args));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    session->handler->machine->write_virtual_memory(address, reinterpret_cast<unsigned char *>(bin.data()), bin.size());
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.translate_virtual_address method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_translate_virtual_address_handler(const json &j,
    const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"vaddr"};
    auto args = parse_args<uint64_t>(j, param_name);
    auto vaddr = std::get<0>(args);
    return jsonrpc_response_ok(j, session->handler->machine->translate_virtual_address(vaddr));
}

/// \brief JSONRPC handler for the machine.replace_memory_range method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_replace_memory_range_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"range"};
    auto args = parse_args<cartesi::memory_range_config>(j, param_name);
    session->handler->machine->replace_memory_range(std::get<0>(args));
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_reg method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_read_reg_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"reg"};
    auto args = parse_args<cartesi::machine::reg>(j, param_name);
    return jsonrpc_response_ok(j, session->handler->machine->read_reg(std::get<0>(args)));
}

/// \brief JSONRPC handler for the machine.write_reg method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_write_reg_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"reg", "value"};
    auto args = parse_args<cartesi::machine::reg, uint64_t>(j, param_name);
    session->handler->machine->write_reg(std::get<0>(args), std::get<1>(args));
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.get_reg_address method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_get_reg_address_handler(const json &j, const std::shared_ptr<http_session> &session) {
    (void) session;
    static const char *param_name[] = {"reg"};
    auto args = parse_args<cartesi::machine::reg>(j, param_name);
    return jsonrpc_response_ok(j, cartesi::machine::get_reg_address(std::get<0>(args)));
}

/// \brief JSONRPC handler for the machine.reset_uarch method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_reset_uarch_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    session->handler->machine->reset_uarch();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.get_initial_config method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_get_initial_config_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, session->handler->machine->get_initial_config());
}

/// \brief JSONRPC handler for the machine.get_default_config method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_get_default_config_handler(const json &j, const std::shared_ptr<http_session> &session) {
    (void) session;
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, cartesi::machine::get_default_config());
}

/// \brief JSONRPC handler for the machine.verify_dirty_page_maps method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_verify_dirty_page_maps_handler(const json &j,
    const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, session->handler->machine->verify_dirty_page_maps());
}

/// \brief JSONRPC handler for the machine.get_memory_ranges method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_get_memory_ranges_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, session->handler->machine->get_memory_ranges());
}

/// \brief JSONRPC handler for the machine.send_cmio_response method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_send_cmio_response_handler(const json &j, const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"reason", "data"};
    auto args = parse_args<uint16_t, std::string>(j, param_name);
    auto bin = cartesi::decode_base64(std::get<1>(args));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    session->handler->machine->send_cmio_response(std::get<0>(args), reinterpret_cast<unsigned char *>(bin.data()),
        bin.size());
    return jsonrpc_response_ok(j);
}

static json jsonrpc_machine_log_send_cmio_response_handler(const json &j,
    const std::shared_ptr<http_session> &session) {
    if (!session->handler->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"reason", "data", "log_type"};
    auto args =
        parse_args<uint16_t, std::string, cartesi::not_default_constructible<cartesi::access_log::type>>(j, param_name);
    auto bin = cartesi::decode_base64(std::get<1>(args));
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    return jsonrpc_response_ok(j,
        session->handler->machine->log_send_cmio_response(std::get<0>(args),
            reinterpret_cast<unsigned char *>(bin.data()), bin.size(), std::get<2>(args).value()));
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    // NOLINTEND(bugprone-unchecked-optional-access)
}

/// \brief JSONRPC handler for the machine.verify_send_cmio_response method
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON response object
static json jsonrpc_machine_verify_send_cmio_response_handler(const json &j,
    const std::shared_ptr<http_session> &session) {
    (void) session;
    static const char *param_name[] = {"reason", "data", "root_hash_before", "log", "root_hash_after"};
    auto args = parse_args<uint16_t, std::string, cartesi::machine_merkle_tree::hash_type,
        cartesi::not_default_constructible<cartesi::access_log>, cartesi::machine_merkle_tree::hash_type>(j,
        param_name);

    auto bin = cartesi::decode_base64(std::get<1>(args));
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    cartesi::machine::verify_send_cmio_response(std::get<0>(args), reinterpret_cast<unsigned char *>(bin.data()),
        bin.size(), std::get<2>(args), std::get<3>(args).value(), std::get<4>(args));
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    // NOLINTEND(bugprone-unchecked-optional-access)
    return jsonrpc_response_ok(j);
}

/// \brief Prepares a JSONRPC response
/// \param req HTTP request object
/// \param j JSON response object
/// \param session HTTP session
/// \returns HTTP response message
http::message_generator jsonrpc_http_reply(const http::request<http::string_body> &req, const json &j,
    const std::shared_ptr<http_session> &session) {
    std::string body = j.dump();
    SLOG(trace) << session->handler->local_endpoint << " response is " << body;
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::access_control_allow_origin, "*");
    res.set(http::field::content_type, "application/json");
    res.body() = std::move(body);
    res.prepare_payload();
    res.keep_alive(req.keep_alive());
    return res;
}

/// \brief Prepares an empty JSONRPC response
/// \param req HTTP request object
/// \param session HTTP session
/// \returns HTTP response message
http::message_generator jsonrpc_http_empty_reply(const http::request<http::string_body> &req,
    const std::shared_ptr<http_session> &session) {
    SLOG(trace) << session->handler->local_endpoint << " response is empty";
    http::response<http::empty_body> res{http::status::ok, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::access_control_allow_origin, "*");
    res.set(http::field::content_type, "application/json");
    res.keep_alive(req.keep_alive());
    return res;
}

/// \brief jsonrpc handler is a function pointer
using jsonrpc_handler = json (*)(const json &ji, const std::shared_ptr<http_session> &session);

/// \brief Dispatch request to appropriate JSONRPC handler
/// \param j JSON request object
/// \param session HTTP session
/// \returns JSON with response
static json jsonrpc_dispatch_method(const json &j, const std::shared_ptr<http_session> &session) try {
    static const std::unordered_map<std::string, jsonrpc_handler> dispatch = {
        {"fork", jsonrpc_fork_handler},
        {"rebind", jsonrpc_rebind_handler},
        {"shutdown", jsonrpc_shutdown_handler},
        {"get_version", jsonrpc_get_version_handler},
        {"rpc.discover", jsonrpc_rpc_discover_handler},
        {"machine.machine.config", jsonrpc_machine_machine_config_handler},
        {"machine.machine.directory", jsonrpc_machine_machine_directory_handler},
        {"machine.destroy", jsonrpc_machine_destroy_handler},
        {"machine.store", jsonrpc_machine_store_handler},
        {"machine.run", jsonrpc_machine_run_handler},
        {"machine.run_uarch", jsonrpc_machine_run_uarch_handler},
        {"machine.log_step_uarch", jsonrpc_machine_log_step_uarch_handler},
        {"machine.reset_uarch", jsonrpc_machine_reset_uarch_handler},
        {"machine.log_reset_uarch", jsonrpc_machine_log_reset_uarch_handler},
        {"machine.verify_reset_uarch", jsonrpc_machine_verify_reset_uarch_handler},
        {"machine.verify_step_uarch", jsonrpc_machine_verify_step_uarch_handler},
        {"machine.get_proof", jsonrpc_machine_get_proof_handler},
        {"machine.get_root_hash", jsonrpc_machine_get_root_hash_handler},
        {"machine.read_word", jsonrpc_machine_read_word_handler},
        {"machine.read_memory", jsonrpc_machine_read_memory_handler},
        {"machine.write_memory", jsonrpc_machine_write_memory_handler},
        {"machine.read_virtual_memory", jsonrpc_machine_read_virtual_memory_handler},
        {"machine.write_virtual_memory", jsonrpc_machine_write_virtual_memory_handler},
        {"machine.translate_virtual_address", jsonrpc_machine_translate_virtual_address_handler},
        {"machine.replace_memory_range", jsonrpc_machine_replace_memory_range_handler},
        {"machine.read_reg", jsonrpc_machine_read_reg_handler},
        {"machine.write_reg", jsonrpc_machine_write_reg_handler},
        {"machine.get_reg_address", jsonrpc_machine_get_reg_address_handler},
        {"machine.get_initial_config", jsonrpc_machine_get_initial_config_handler},
        {"machine.get_default_config", jsonrpc_machine_get_default_config_handler},
        {"machine.verify_merkle_tree", jsonrpc_machine_verify_merkle_tree_handler},
        {"machine.verify_dirty_page_maps", jsonrpc_machine_verify_dirty_page_maps_handler},
        {"machine.get_memory_ranges", jsonrpc_machine_get_memory_ranges_handler},
        {"machine.send_cmio_response", jsonrpc_machine_send_cmio_response_handler},
        {"machine.log_send_cmio_response", jsonrpc_machine_log_send_cmio_response_handler},
        {"machine.verify_send_cmio_response", jsonrpc_machine_verify_send_cmio_response_handler},
    };
    auto method = j["method"].get<std::string>();
    SLOG(debug) << session->handler->local_endpoint << " handling \"" << method << "\" method";
    auto found = dispatch.find(method);
    if (found != dispatch.end()) {
        return found->second(j, session);
    }
    return jsonrpc_response_method_not_found(j, method);
} catch (std::invalid_argument &x) {
    return jsonrpc_response_invalid_params(j, x.what());
} catch (std::exception &x) {
    return jsonrpc_response_internal_error(j, x.what());
}

//------------------------------------------------------------------------------

/// \brief Handler for HTTP requests
/// \param req HTTP request
/// \param session HTTP session
// Return a response for the given request.
template <typename HTTP_REQ>
http::message_generator handle_request(HTTP_REQ &&rreq,
    const std::shared_ptr<http_session> &session) {
    static_assert(std::is_same_v<std::remove_cvref_t<HTTP_REQ>, http::request<http::string_body>>, "not a boost::beast::http::request<http::string_body>>");
    HTTP_REQ req = std::forward<HTTP_REQ>(rreq);
    // Answer OPTIONS request to support cross origin resource sharing (CORS) preflighted browser requests
    if (req.method() == http::verb::options) {
        SLOG(trace) << session->handler->local_endpoint << " serving \"" << req.method_string() << "\" request";
        http::response<http::empty_body> res{http::status::no_content, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "*");
        res.set(http::field::access_control_allow_headers, "*");
        res.set(http::field::access_control_max_age, "0");
        res.keep_alive(req.keep_alive());
        return res;
    }
    // Only accept POST requests
    if (req.method() != http::verb::post) {
        SLOG(trace) << session->handler->local_endpoint << " rejected unexpected \"" << req.method_string()
                    << "\" request";
        http::response<http::empty_body> res{http::status::method_not_allowed, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::access_control_allow_origin, "*");
        res.keep_alive(req.keep_alive());
        return res;
    }
    // Only accept / URI
    if (req.target() != "/") {
        SLOG(trace) << session->handler->local_endpoint << " rejected unexpected \"" << req.target() << "\" uri";
        http::response<http::empty_body> res{http::status::not_found, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::access_control_allow_origin, "*");
        res.keep_alive(req.keep_alive());
        return res;
    }
    SLOG(trace) << session->handler->local_endpoint << " request is " << req.target();
    // Parse request body into a JSON object
    json j;
    try {
        j = json::parse(req.body().data());
    } catch (std::exception &x) {
        return jsonrpc_http_reply(req, jsonrpc_response_parse_error(x.what()), session);
    }
    // JSONRPC allows batch requests, each an entry in an array
    // We deal uniformly with batch and singleton requests by wrapping the singleton into a batch
    auto was_array = j.is_array();
    if (!was_array) {
        j = json::array({std::move(j)});
    }
    if (j.empty()) {
        return jsonrpc_http_reply(req, jsonrpc_response_invalid_request(j, "empty batch request array"), session);
    }
    json jr;
    // Obtain response to each request in batch
    for (auto ji : j) {
        if (!ji.is_object()) {
            jr.push_back(jsonrpc_response_invalid_request(ji, "request not an object"));
            continue;
        }
        if (!ji.contains("jsonrpc")) {
            jr.push_back(jsonrpc_response_invalid_request(ji, "missing field \"jsonrpc\""));
            continue;
        }
        if (!ji["jsonrpc"].is_string() || ji["jsonrpc"] != "2.0") {
            jr.push_back(jsonrpc_response_invalid_request(ji, R"(invalid field "jsonrpc" (expected "2.0"))"));
            continue;
        }
        if (!ji.contains("method")) {
            jr.push_back(jsonrpc_response_invalid_request(ji, "missing field \"method\""));
            continue;
        }
        if (!ji["method"].is_string() || ji["method"].get<std::string>().empty()) {
            jr.push_back(jsonrpc_response_invalid_request(ji, "invalid field \"method\" (expected non-empty string)"));
            continue;
        }
        // check for valid id
        if (ji.contains("id")) {
            const auto &jiid = ji["id"];
            if (!jiid.is_string() && !jiid.is_number() && !jiid.is_null()) {
                jr.push_back(
                    jsonrpc_response_invalid_request(ji, "invalid field \"id\" (expected string, number, or null)"));
            }
        }
        json jri = jsonrpc_dispatch_method(ji, session);
        // Except for errors, do not add result of "notification" requests
        if (ji.contains("id")) {
            jr.push_back(std::move(jri));
        }
    }
    // Unwrap singleton request from batch, if it was indeed a singleton
    // Otherwise, just send the response
    if (!jr.empty()) {
        if (was_array) {
            return jsonrpc_http_reply(req, jr, session);
        }
        return jsonrpc_http_reply(req, jr[0], session);
    }
    return jsonrpc_http_empty_reply(req, session);
}

/// \brief Prints help message
/// \param name Executable name
static void help(const char *name) {
    (void) fprintf(stderr,
        R"(Usage:

    %s [options]

where options are

    --server-address=<server-address>
      gives the address server should bind to
      <server-address> can be
        <ipv4-address>:<port>
        <ipv6-address>:<port>
      when <port> is 0, an ephemeral port will be automatically selected
      default is "127.0.0.1:0"

    --server-fd=<socket-fd>
      use a listening TCP/IP socket file descriptor inherited from parent process
      default is "-1", so a new socket is created based on --server-address

    --setpgid
      break out of parent process group and become leader of new group
      (this essentially puts the server in the background)
      the proccess group id is the same as the process id of the server
      the server and all its children can be signaled via this process group id

    --sigusr1
      send SIGUSR1 to parent process when ready

    --log-level=<level>
      sets the log level
      <level> can be
        trace
        debug
        info
        warn
        error
        fatal
      the command line option takes precedence over the environment variable
      REMOTE_CARTESI_MACHINE_LOG_LEVEL

    --help
      prints this message and exits

)",
        name);
}

/// \brief Checks if string matches prefix and captures remainder
/// \param pre Prefix to match in str.
/// \param str Input string
/// \param val If string matches prefix, points to remainder
/// \returns True if string matches prefix, false otherwise
static bool stringval(const char *pre, const char *str, const char **val) {
    const size_t len = strlen(pre);
    if (strncmp(pre, str, len) == 0) {
        *val = str + len;
        return true;
    }
    return false;
}

static void init_logger(const char *strlevel) {
    using namespace slog;
    severity_level level = severity_level::info;
    if (!strlevel) {
        strlevel = std::getenv("REMOTE_CARTESI_MACHINE_LOG_LEVEL");
    }
    if (strlevel) {
        level = from_string(strlevel);
    }
    log_level(level_operation::set, level);
}

int main(int argc, char *argv[]) try {
    const char *server_address = nullptr;
    int server_fd = -1;
    bool newpg = false;
    bool sigusr1 = false;
    const char *log_level = nullptr;
    const char *program_name = PROGRAM_NAME;

    if (argc > 0) { // NOLINT: of course it could be == 0...
        program_name = argv[0];
    }

    for (int i = 1; i < argc; i++) {
        if (stringval("--server-address=", argv[i], &server_address)) {
            ;
        // NOLINTNEXTLINE(cert-err34-c)
        } else if (int end = 0; sscanf(argv[i], "--server-fd=%d%n", &server_fd, &end) == 1 && argv[i][end] == 0) {
            ;
        } else if (stringval("--log-level=", argv[i], &log_level)) {
            ;
        } else if (strcmp(argv[i], "--setpgid") == 0) {
            newpg = true;
        } else if (strcmp(argv[i], "--sigusr1") == 0) {
            sigusr1 = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            help(program_name);
            exit(0);
        } else {
            std::cerr << "invalid command-line argument '" << argv[i] << "'\n";
            exit(1);
        }
    }

    // create a new process group and become its leader
    if (newpg) {
        setpgid(0, 0);
        SLOG(info) << "remote machine server now has pgid:" << getpgid(0);
    }

    if (sigusr1) {
        kill(getppid(), SIGUSR1);
    }

    init_logger(log_level);

    SLOG(info) << "remote machine server version is " << server_version_major << "." << server_version_minor << "."
               << server_version_patch;

    install_restart_signal_handlers();

    // IO context that will process async events
    asio::io_context ioc{1};

    tcp::acceptor acceptor(ioc);
    if (server_fd >= 0) {
        if (server_address) {
            SLOG(fatal) << "server-address and server-fd options are mutually exclusive";
            exit(1);
        }
        SLOG(info) << "attempting to inherit fd " << server_fd << " from parent";
        // check socket is listening and is of right domain and type
        struct sockaddr_in fd_addr{};
        socklen_t len = sizeof(fd_addr);
        memset(&fd_addr, 0, len);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        if (getsockname(server_fd, reinterpret_cast<struct sockaddr *>(&fd_addr), &len) < 0) {
            SLOG(fatal) << "getsockname failed on inherited fd: " << strerror(errno);
            exit(1);
        }
        if (fd_addr.sin_family != PF_INET && fd_addr.sin_family != PF_INET6) {
            SLOG(fatal) << "inherited fd is not an inet/inet6 domain socket";
            exit(1);
        }
        int listen = 0;
        len = sizeof(listen);
        if (getsockopt(server_fd, SOL_SOCKET, SO_ACCEPTCONN, &listen, &len) < 0) {
            auto copy = errno;
            if (copy != ENOPROTOOPT) {
                SLOG(fatal) << "getsockopt failed on inherited fd: " << strerror(errno);
                exit(1);
            } else { // test is not supported in platform (e.g. macOS), so we just hope for the best
                listen = 1;
            }
        }
        if (!listen) {
            SLOG(fatal) << "inherited is fd not a listening socket";
            exit(1);
        }
        int type = 0;
        len = sizeof(type);
        if (getsockopt(server_fd, SOL_SOCKET, SO_TYPE, &type, &len) < 0) {
            SLOG(fatal) << "getsockopt failed on inherited fd: " << strerror(errno);
            exit(1);
        }
        if (type != SOCK_STREAM) {
            SLOG(fatal) << "inherited fd is not a stream type socket";
            exit(1);
        }
        if (fd_addr.sin_family == PF_INET) {
            acceptor.assign(boost::asio::ip::tcp::v4(), server_fd);
        } else {
            acceptor.assign(boost::asio::ip::tcp::v6(), server_fd);
        }
    } else {
        if (!server_address) {
            server_address = "127.0.0.1:0";
        }
        acceptor = tcp::acceptor{ioc, address_to_endpoint(server_address)};
    }

    SLOG(info) << "initial server address is '" << acceptor.local_endpoint() << "'";

    // Create and launch a listener
    auto handler = std::make_shared<http_handler>(ioc, std::move(acceptor));
    // Begin asynchronous operation that will be fired on next process termination signal
    handler->install_termination_signal_handlers();
    // Begin asynchronous operation that will be fired on next accept
    handler->next_accept();

    // Run until there is no pending asynchronous events anymore,
    // e.g, there is no more clients connected and the handler is not accepting new connections.
    ioc.run();

    SLOG(trace) << "remote machine server exiting";
    return 0;
} catch (std::exception &e) {
    SLOG(fatal) << "caught exception: " << e.what();
    return 1;
} catch (...) {
    SLOG(fatal) << "caught unknown exception";
    return 1;
}
