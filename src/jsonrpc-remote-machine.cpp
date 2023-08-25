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
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <variant>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <json.hpp>
#include <mongoose.h>

#include "base64.h"
#include "json-util.h"
#include "jsonrpc-discover.h"
#include "machine.h"
#include "unique-c-ptr.h"

#define SLOG_PREFIX log_prefix
#include "slog.h"

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define PROGRAM_NAME "jsonrpc-remote-cartesi-machine"

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
    return out;
}

using namespace std::string_literals;
using json = nlohmann::json;

/// \brief Server semantic version major
static constexpr uint32_t server_version_major = 0;
/// \brief Server semantic version minor
static constexpr uint32_t server_version_minor = 1;
/// \brief Server semantic version patch
static constexpr uint32_t server_version_patch = 1;
/// \brief Server semantic version pre_release
static constexpr const char *server_version_pre_release = "";
/// \brief Server semantic version build
static constexpr const char *server_version_build = "";

/// \brief Volatile variable to abort server loop in case of signal
static volatile bool abort_due_to_signal = false; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

/// \brief Volatile variables to report relevant signals that were observed
static volatile bool SIGTERM_caught = false; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static volatile bool SIGINT_caught = false;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static volatile bool SIGBUS_caught = false;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

/// \brief Name and pointer to caught-Boolean for a signal
/// \detail Using std::pair would have been easier but its default constructor
/// is not marked as noexcept
struct signal_to_log {
    const char *name;
    volatile bool *caught;
};

/// \brief Signals to log when caught
static const std::array<signal_to_log, 3> signals_to_log = {
    {{"SIGTERM", &SIGTERM_caught}, {"SIGINT", &SIGINT_caught}, {"SIGBUS", &SIGBUS_caught}}};

/// \brief Signal handler installed for SIGTERM
/// \param signal Signal number (will be SIGTERM)
static void signal_handler_SIGTERM(int signal) {
    (void) signal;
    // Set variable to report signal in log
    SIGTERM_caught = true;
    // Set variable to break out from server loop
    abort_due_to_signal = true;
}

/// \brief Signal handler installed for SIGINT
/// \param signal Signal number (will be SIGINT)
static void signal_handler_SIGINT(int signal) {
    (void) signal;
    // Set variable to report signal in log
    SIGINT_caught = true;
    // Set variable to break out from server loop
    abort_due_to_signal = true;
}

/// \brief Signal handler installed for SIGBUS
/// \param signal Signal number (will be SIGBUS)
static void signal_handler_SIGBUS(int signal) {
    (void) signal;
    // Set variable to report signal in log
    SIGBUS_caught = true;
    // Set variable to break out from server loop
    abort_due_to_signal = true;
}

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

/// \brief Installs all signal handlers
static void install_signal_handlers(void) {
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
    // Set variable to break server loop and exit
    install_signal_handler(SIGTERM, signal_handler_SIGTERM);
    install_signal_handler(SIGINT, signal_handler_SIGINT);
    install_signal_handler(SIGBUS, signal_handler_SIGBUS);
}

/// \brief Log all signals caught
/// \detail If a signal that is currently marked for reporting is caught while this function is executing,
/// the second signal instance might get lost. Solving this potential issue is not worth the excruciating trouble
static void log_signals(void) {
    for (const auto &signal : signals_to_log) {
        if (*signal.caught) {
            SLOG(trace) << signal.name << " caught";
            *signal.caught = false;
        }
    }
}

/// \brief Closes event manager without interfering with other processes
/// \param event_manager Pointer to event manager to close
/// \detail Mongoose's mg_mgr_free removes all sockets from the epoll_fd, which affects other processes.
/// We close the epoll_fd first to prevent this problem
static void mg_mgr_free_ours(mg_mgr *event_manager) {
#ifdef MG_ENABLE_EPOLL
    // Prevent destruction of manager from affecting the epoll state of parent
    close(event_manager->epoll_fd);
    event_manager->epoll_fd = -1;
#endif
    mg_mgr_free(event_manager);
}

/// \brief HTTP handler status
enum class http_handler_status {
    ready_for_next, ///< Ready for next request in loop
    forked_child,   ///< Previous request forked a child and the child is continuing the loop
    shutdown        ///< Previous request was for shutdown
};

/// \brief HTTP handler data
struct http_handler_data {
    std::string server_address;                ///< Address server receives requests at
    std::unique_ptr<cartesi::machine> machine; ///< Cartesi Machine, if any
    http_handler_status status;                ///< Status of last request
    mg_mgr event_manager;                      ///< Mongoose event manager
    struct http_handler_data *child;           ///< Pointer to handler data for forked child now running, if any
};

/// \brief Forward declaration of http handler
static void http_handler(mg_connection *con, int ev, void *ev_data, void *h_data);

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
    return ((!is_optional_param_v<ARGS> ? 0 : 1) + ... + 0);
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
/// \details This is the overload for optional paramenters (i.e., wrapped in optional_param)
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
/// \param tup Tupple with all arguments
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
/// \param tup Tupple with all arguments
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
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_shutdown_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) h;
    jsonrpc_check_no_params(j);
    con->is_draining = 1;
    con->data[0] = 'X';
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for rpc.discover method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
/// \details This RPC allows a client to download the entire schema of the service
static json jsonrpc_rpc_discover_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) h;
    (void) con;
    const static json schema = json::parse(cartesi::jsonrpc_discover_json);
    return jsonrpc_response_ok(j, schema);
}

/// \brief JSONRPC handler for the get_version method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_get_version_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) h;
    (void) con;
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

/// \brief Replaces the port specification (i.e., after ':') in an address with a new port
/// \param address Original address
/// \param port New port
/// \return New address with replaced port
static std::string replace_port(const std::string &address, int port) {
    auto pos = address.find_last_of(':');
    // If already has a port, replace
    if (pos != std::string::npos) {
        return address.substr(0, pos) + ":" + std::to_string(port);
        // Otherwise, concatenate
    } else {
        return address + ":" + std::to_string(port);
    }
}

/// \brief JSONRPC handler for the fork method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
/// \details Here we allocate a new server that will be used by the child, then we fork.
/// The child will later destroy the old server it inherited from the parent and replace it with the new one.
/// The parent reports the address of the new server back to the client, and destroys its copy of the child's new
/// server. The parent goes on to continue serving from the old server. The child goes on to start serving from the new
/// server.
static json jsonrpc_fork_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    jsonrpc_check_no_params(j);
    // Initialize child's server before fork so failures happen still in parent, who can directly report them to client
    h->child = new (std::nothrow) http_handler_data{};
    if (!h->child) {
        SLOG(fatal) << h->server_address << " out of memory";
        return jsonrpc_response_server_error(j, "out of memory");
    }
    mg_mgr_init(&h->child->event_manager);
#if MG_ENABLE_EPOLL
    // Event manager initialization does not return whether it failed or not
    // It could only fail if the epoll_fd allocation failed
    if (h->child->event_manager.epoll_fd < 0) {
        SLOG(error) << h->server_address << " failed creating event manager";
        mg_mgr_free(&h->child->event_manager);
        delete h->child;
        h->child = nullptr;
        return jsonrpc_response_server_error(j, "failed creating event manager");
    }
#endif
    const std::string any_port_address = replace_port(h->server_address, 0);
    mg_connection *new_con = mg_http_listen(&h->child->event_manager, any_port_address.c_str(), http_handler, h->child);
    if (!new_con) {
        SLOG(error) << h->server_address << " failed listening";
        mg_mgr_free(&h->child->event_manager);
        delete h->child;
        h->child = nullptr;
        return jsonrpc_response_server_error(j, "failed listening");
    }
    const std::string new_server_address = replace_port(h->server_address, static_cast<int>(ntohs(new_con->loc.port)));
    // Done initializing, so we fork
    auto ret = fork();
    if (ret == -1) { // failed forking
        auto errno_copy = errno;
        SLOG(error) << h->server_address << " fork failed (" << strerror(errno_copy) << ")";
        mg_mgr_free(&h->child->event_manager);
        delete h->child;
        h->child = nullptr;
        return jsonrpc_response_server_error(j, "fork failed ("s + strerror(errno_copy) + ")"s);
    }
    if (ret == 0) { // child
        // The child doesn't need the event_manager it inherited from the parent.
        // However, it would be impolite to destroy it here, since it would be somewhat unexpected (reentrant?).
        // I.e., we are currently in a function that was invoked from within mg_mgr_poll.
        // So we return with a status and destroy the event_manager only after mg_mgr_poll returns in our loop.
        h->status = http_handler_status::forked_child;
        h->child->server_address = new_server_address;
        h->child->machine = std::move(h->machine);
        return json{};
    }
    // parent
    // The parent doesn't need the server that will be used by the child
    mg_mgr_free_ours(&h->child->event_manager);
    delete h->child;
    h->child = nullptr;
    return jsonrpc_response_ok(j, new_server_address);
}

/// \brief JSONRPC handler for the machine.machine.directory method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_machine_directory_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (h->machine) {
        return jsonrpc_response_invalid_request(j, "machine exists");
    }
    static const char *param_name[] = {"directory", "runtime"};
    auto args = parse_args<std::string, cartesi::optional_param<cartesi::machine_runtime_config>>(j, param_name);
    switch (count_args(args)) {
        case 1:
            h->machine = std::make_unique<cartesi::machine>(std::get<0>(args));
            break;
        case 2:
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            h->machine = std::make_unique<cartesi::machine>(std::get<0>(args), std::get<1>(args).value());
            break;
        default:
            throw std::runtime_error{"error detecting number of arguments"};
    }
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.machine.config method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_machine_config_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (h->machine) {
        return jsonrpc_response_invalid_request(j, "machine exists");
    }
    static const char *param_name[] = {"config", "runtime"};
    auto args =
        parse_args<cartesi::machine_config, cartesi::optional_param<cartesi::machine_runtime_config>>(j, param_name);
    switch (count_args(args)) {
        case 1:
            h->machine = std::make_unique<cartesi::machine>(std::get<0>(args));
            break;
        case 2:
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            h->machine = std::make_unique<cartesi::machine>(std::get<0>(args), std::get<1>(args).value());
            break;
        default:
            throw std::runtime_error{"error detecting number of arguments"};
    }
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.destroy method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_destroy_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    jsonrpc_check_no_params(j);
    h->machine.reset();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.store method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_store_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"directory"};
    auto args = parse_args<std::string>(j, param_name);
    h->machine->store(std::get<0>(args));
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
        case R::reached_target_mcycle:
            return "reached_target_mcycle";
    }
    throw std::domain_error{"invalid interpreter break reason"};
}

/// \brief JSONRPC handler for the machine.run method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_run_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"mcycle_end"};
    auto args = parse_args<uint64_t>(j, param_name);
    auto reason = h->machine->run(std::get<0>(args));
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
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_run_uarch_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"uarch_cycle_end"};
    auto args = parse_args<uint64_t>(j, param_name);
    auto reason = h->machine->run_uarch(std::get<0>(args));
    return jsonrpc_response_ok(j, uarch_interpreter_break_reason_name(reason));
}

/// \brief JSONRPC handler for the machine.step_uarch method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_step_uarch_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"log_type", "one_based"};
    auto args =
        parse_args<cartesi::not_default_constructible<cartesi::access_log::type>, cartesi::optional_param<bool>>(j,
            param_name);
    json s;
    switch (count_args(args)) {
        case 1:
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            s = jsonrpc_response_ok(j, h->machine->step_uarch(std::get<0>(args).value()));
            break;
        case 2:
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            s = jsonrpc_response_ok(j, h->machine->step_uarch(std::get<0>(args).value(), std::get<1>(args).value()));
            break;
        default:
            throw std::runtime_error{"error detecting number of arguments"};
    }
    return s;
}

/// \brief JSONRPC handler for the machine.verify_access_log method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_verify_access_log_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    (void) h;
    static const char *param_name[] = {"log", "runtime", "one_based"};
    auto args = parse_args<cartesi::not_default_constructible<cartesi::access_log>,
        cartesi::optional_param<cartesi::machine_runtime_config>, cartesi::optional_param<bool>>(j, param_name);
    switch (count_args(args)) {
        case 1:
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            cartesi::machine::verify_access_log(std::get<0>(args).value());
            break;
        case 2:
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            cartesi::machine::verify_access_log(std::get<0>(args).value(), std::get<1>(args).value());
            break;
        case 3:
            // NOLINTBEGIN(bugprone-unchecked-optional-access)
            cartesi::machine::verify_access_log(std::get<0>(args).value(), std::get<1>(args).value(),
                std::get<2>(args).value());
            // NOLINTEND(bugprone-unchecked-optional-access)
            break;
        default:
            throw std::runtime_error{"error detecting number of arguments"};
    }
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.verify_state_transition method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_verify_state_transition_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    (void) h;
    static const char *param_name[] = {"root_hash_before", "log", "root_hash_after", "runtime", "one_based"};
    auto args = parse_args<cartesi::machine_merkle_tree::hash_type,
        cartesi::not_default_constructible<cartesi::access_log>, cartesi::machine_merkle_tree::hash_type,
        cartesi::optional_param<cartesi::machine_runtime_config>, cartesi::optional_param<bool>>(j, param_name);
    switch (count_args(args)) {
        case 3:
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            cartesi::machine::verify_state_transition(std::get<0>(args), std::get<1>(args).value(), std::get<2>(args));
            break;
        case 4:
            // NOLINTBEGIN(bugprone-unchecked-optional-access)
            cartesi::machine::verify_state_transition(std::get<0>(args), std::get<1>(args).value(), std::get<2>(args),
                std::get<3>(args).value());
            // NOLINTEND(bugprone-unchecked-optional-access)
            break;
        case 5:
            // NOLINTBEGIN(bugprone-unchecked-optional-access)
            cartesi::machine::verify_state_transition(std::get<0>(args), std::get<1>(args).value(), std::get<2>(args),
                std::get<3>(args).value(), std::get<4>(args).value());
            // NOLINTEND(bugprone-unchecked-optional-access)
            break;
        default:
            throw std::runtime_error{"error detecting number of arguments"};
    }
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.get_proof method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_get_proof_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "log2_size"};
    auto args = parse_args<uint64_t, uint64_t>(j, param_name);
    if (std::get<1>(args) > INT_MAX) {
        throw std::domain_error("log2_size is out of range");
    }
    return jsonrpc_response_ok(j, h->machine->get_proof(std::get<0>(args), static_cast<int>(std::get<1>(args))));
}

/// \brief JSONRPC handler for the machine.verify_merkle_tree method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_verify_merkle_tree_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, h->machine->verify_merkle_tree());
}

/// \brief JSONRPC handler for the machine.get_root_hash method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_get_root_hash_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    cartesi::machine_merkle_tree::hash_type hash;
    h->machine->get_root_hash(hash);
    return jsonrpc_response_ok(j, cartesi::encode_base64(hash));
}

/// \brief JSONRPC handler for the machine.read_word method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_word_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address"};
    auto args = parse_args<uint64_t>(j, param_name);
    auto address = std::get<0>(args);
    return jsonrpc_response_ok(j, h->machine->read_word(address));
}

/// \brief JSONRPC handler for the machine.read_memory method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_memory_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "length"};
    auto args = parse_args<uint64_t, uint64_t>(j, param_name);
    auto address = std::get<0>(args);
    auto length = std::get<1>(args);
    auto data = cartesi::unique_calloc<unsigned char>(length);
    h->machine->read_memory(address, data.get(), length);
    return jsonrpc_response_ok(j, cartesi::encode_base64(data.get(), length));
}

/// \brief JSONRPC handler for the machine.write_memory method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_write_memory_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "data"};
    auto args = parse_args<uint64_t, std::string>(j, param_name);
    auto address = std::get<0>(args);
    auto bin = cartesi::decode_base64(std::get<1>(args));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    h->machine->write_memory(address, reinterpret_cast<unsigned char *>(bin.data()), bin.size());
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_virtual_memory method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_virtual_memory_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "length"};
    auto args = parse_args<uint64_t, uint64_t>(j, param_name);
    auto address = std::get<0>(args);
    auto length = std::get<1>(args);
    auto data = cartesi::unique_calloc<unsigned char>(length);
    h->machine->read_virtual_memory(address, data.get(), length);
    return jsonrpc_response_ok(j, cartesi::encode_base64(data.get(), length));
}

/// \brief JSONRPC handler for the machine.write_virtual_memory method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_write_virtual_memory_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"address", "data"};
    auto args = parse_args<uint64_t, std::string>(j, param_name);
    auto address = std::get<0>(args);
    auto bin = cartesi::decode_base64(std::get<1>(args));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    h->machine->write_virtual_memory(address, reinterpret_cast<unsigned char *>(bin.data()), bin.size());
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.replace_memory_range method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_replace_memory_range_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"range"};
    auto args = parse_args<cartesi::memory_range_config>(j, param_name);
    h->machine->replace_memory_range(std::get<0>(args));
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_csr method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_csr_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"csr"};
    auto args = parse_args<cartesi::machine::csr>(j, param_name);
    return jsonrpc_response_ok(j, h->machine->read_csr(std::get<0>(args)));
}

/// \brief JSONRPC handler for the machine.write_csr method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_write_csr_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"csr", "value"};
    auto args = parse_args<cartesi::machine::csr, uint64_t>(j, param_name);
    h->machine->write_csr(std::get<0>(args), std::get<1>(args));
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_x method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_x_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"index"};
    auto args = parse_args<uint64_t>(j, param_name);
    const int i = static_cast<int>(std::get<0>(args));
    if (i >= cartesi::X_REG_COUNT) {
        throw std::domain_error{"index out of range"};
    }
    return jsonrpc_response_ok(j, h->machine->read_x(i));
}

/// \brief JSONRPC handler for the machine.write_x method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_write_x_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"index", "value"};
    auto args = parse_args<uint64_t, uint64_t>(j, param_name);
    const int i = static_cast<int>(std::get<0>(args));
    if (i >= cartesi::X_REG_COUNT || i == 0) {
        throw std::domain_error{"index out of range"};
    }
    h->machine->write_x(i, std::get<1>(args));
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_f method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_f_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"index"};
    auto args = parse_args<uint64_t>(j, param_name);
    const int i = static_cast<int>(std::get<0>(args));
    if (i >= cartesi::F_REG_COUNT) {
        throw std::domain_error{"index out of range"};
    }
    return jsonrpc_response_ok(j, h->machine->read_f(i));
}

/// \brief JSONRPC handler for the machine.write_f method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_write_f_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"index", "value"};
    auto args = parse_args<uint64_t, uint64_t>(j, param_name);
    const int i = static_cast<int>(std::get<0>(args));
    if (i >= cartesi::F_REG_COUNT) {
        throw std::domain_error{"index out of range"};
    }
    h->machine->write_f(i, std::get<1>(args));
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_uarch_x method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_uarch_x_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"index"};
    auto args = parse_args<uint64_t>(j, param_name);
    const int i = static_cast<int>(std::get<0>(args));
    if (i >= cartesi::UARCH_X_REG_COUNT) {
        throw std::domain_error{"index out of range"};
    }
    return jsonrpc_response_ok(j, h->machine->read_uarch_x(i));
}

/// \brief JSONRPC handler for the machine.write_uarch_x method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_write_uarch_x_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    static const char *param_name[] = {"index", "value"};
    auto args = parse_args<uint64_t, uint64_t>(j, param_name);
    const int i = static_cast<int>(std::get<0>(args));
    if (i >= cartesi::UARCH_X_REG_COUNT || i == 0) {
        throw std::domain_error{"index out of range"};
    }
    h->machine->write_uarch_x(i, std::get<1>(args));
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.get_csr_address method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_get_csr_address_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    (void) h;
    static const char *param_name[] = {"csr"};
    auto args = parse_args<cartesi::machine::csr>(j, param_name);
    return jsonrpc_response_ok(j, cartesi::machine::get_csr_address(std::get<0>(args)));
}

/// \brief JSONRPC handler for the machine.get_x_address method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_get_x_address_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    (void) h;
    static const char *param_name[] = {"index"};
    auto args = parse_args<uint64_t>(j, param_name);
    const int i = static_cast<int>(std::get<0>(args));
    if (i >= cartesi::X_REG_COUNT) {
        throw std::domain_error{"index out of range"};
    }
    return jsonrpc_response_ok(j, cartesi::machine::get_x_address(i));
}

/// \brief JSONRPC handler for the machine.get_f_address method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_get_f_address_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    (void) h;
    static const char *param_name[] = {"index"};
    auto args = parse_args<uint64_t>(j, param_name);
    const int i = static_cast<int>(std::get<0>(args));
    if (i >= cartesi::F_REG_COUNT) {
        throw std::domain_error{"index out of range"};
    }
    return jsonrpc_response_ok(j, cartesi::machine::get_f_address(i));
}

/// \brief JSONRPC handler for the machine.get_uarch_x_address method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_get_uarch_x_address_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    (void) h;
    static const char *param_name[] = {"index"};
    auto args = parse_args<uint64_t>(j, param_name);
    const int i = static_cast<int>(std::get<0>(args));
    if (i >= cartesi::UARCH_X_REG_COUNT) {
        throw std::domain_error{"index out of range"};
    }
    return jsonrpc_response_ok(j, cartesi::machine::get_uarch_x_address(i));
}

/// \brief JSONRPC handler for the machine.reset_iflags_Y method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_reset_iflags_Y_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    h->machine->reset_iflags_Y();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.set_iflags_Y method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_set_iflags_Y_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    h->machine->set_iflags_Y();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_iflags_Y method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_iflags_Y_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, h->machine->read_iflags_Y());
}

/// \brief JSONRPC handler for the machine.set_iflags_X method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_set_iflags_X_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    h->machine->set_iflags_X();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.reset_iflags_X method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_reset_iflags_X_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    h->machine->reset_iflags_X();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_iflags_X method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_iflags_X_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, h->machine->read_iflags_X());
}

/// \brief JSONRPC handler for the machine.set_iflags_H method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_set_iflags_H_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    h->machine->set_iflags_H();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_iflags_H method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_iflags_H_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, h->machine->read_iflags_H());
}

/// \brief JSONRPC handler for the machine.read_iflags_PRV method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_iflags_PRV_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, static_cast<uint64_t>(h->machine->read_iflags_PRV()));
}

/// \brief JSONRPC handler for the machine.set_uarch_halt_flag method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_set_uarch_halt_flag_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    h->machine->set_uarch_halt_flag();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.reset_uarch_state method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_reset_uarch_state_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    h->machine->reset_uarch_state();
    return jsonrpc_response_ok(j);
}

/// \brief JSONRPC handler for the machine.read_uarch_halt_flag method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_read_uarch_halt_flag_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, h->machine->read_uarch_halt_flag());
}

/// \brief JSONRPC handler for the machine.get_initial_config method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_get_initial_config_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, h->machine->get_initial_config());
}

/// \brief JSONRPC handler for the machine.get_default_config method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_get_default_config_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) h;
    (void) con;
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, cartesi::machine::get_default_config());
}

/// \brief JSONRPC handler for the machine.verify_dirty_page_maps method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_verify_dirty_page_maps_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    return jsonrpc_response_ok(j, h->machine->verify_dirty_page_maps());
}

/// \brief JSONRPC handler for the machine.dump_pmas method
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h Handler data
/// \returns JSON response object
static json jsonrpc_machine_dump_pmas_handler(const json &j, mg_connection *con, http_handler_data *h) {
    (void) con;
    if (!h->machine) {
        return jsonrpc_response_invalid_request(j, "no machine");
    }
    jsonrpc_check_no_params(j);
    h->machine->dump_pmas();
    return jsonrpc_response_ok(j);
}

/// \brief Sends a JSONRPC response through the Mongoose connection
/// \param con Mongoose connection
/// \param j JSON response object
void jsonrpc_http_reply(mg_connection *con, http_handler_data *h, const json &j) {
    SLOG(trace) << h->server_address << " response is " << j.dump().data();
    return mg_http_reply(con, 200, "Access-Control-Allow-Origin: *\r\nContent-Type: application/json\r\n", "%s",
        j.dump().data());
}

/// \brief Sends an empty response through the Mongoose connection
/// \param con Mongoose connection
void jsonrpc_send_empty_reply(mg_connection *con, http_handler_data *h) {
    SLOG(trace) << h->server_address << " response is empty";
    return mg_http_reply(con, 200, "Access-Control-Allow-Origin: *\r\nContent-Type: application/json\r\n", "");
}

/// \brief jsonrpc handler is a function pointer
using jsonrpc_handler = json (*)(const json &ji, mg_connection *con, http_handler_data *h);

/// \brief Dispatch request to appropriate JSONRPC handler
/// \param j JSON request object
/// \param con Mongoose connection
/// \param h_data Handler data
/// \returns JSON with response
static json jsonrpc_dispatch_method(const json &j, mg_connection *con, http_handler_data *h) try {
    static const std::unordered_map<std::string, jsonrpc_handler> dispatch = {
        {"fork", jsonrpc_fork_handler},
        {"shutdown", jsonrpc_shutdown_handler},
        {"get_version", jsonrpc_get_version_handler},
        {"rpc.discover", jsonrpc_rpc_discover_handler},
        {"machine.machine.config", jsonrpc_machine_machine_config_handler},
        {"machine.machine.directory", jsonrpc_machine_machine_directory_handler},
        {"machine.destroy", jsonrpc_machine_destroy_handler},
        {"machine.store", jsonrpc_machine_store_handler},
        {"machine.run", jsonrpc_machine_run_handler},
        {"machine.run_uarch", jsonrpc_machine_run_uarch_handler},
        {"machine.step_uarch", jsonrpc_machine_step_uarch_handler},
        {"machine.verify_access_log", jsonrpc_machine_verify_access_log_handler},
        {"machine.verify_state_transition", jsonrpc_machine_verify_state_transition_handler},
        {"machine.get_proof", jsonrpc_machine_get_proof_handler},
        {"machine.get_root_hash", jsonrpc_machine_get_root_hash_handler},
        {"machine.read_word", jsonrpc_machine_read_word_handler},
        {"machine.read_memory", jsonrpc_machine_read_memory_handler},
        {"machine.write_memory", jsonrpc_machine_write_memory_handler},
        {"machine.read_virtual_memory", jsonrpc_machine_read_virtual_memory_handler},
        {"machine.write_virtual_memory", jsonrpc_machine_write_virtual_memory_handler},
        {"machine.replace_memory_range", jsonrpc_machine_replace_memory_range_handler},
        {"machine.read_csr", jsonrpc_machine_read_csr_handler},
        {"machine.write_csr", jsonrpc_machine_write_csr_handler},
        {"machine.get_csr_address", jsonrpc_machine_get_csr_address_handler},
        {"machine.read_x", jsonrpc_machine_read_x_handler},
        {"machine.write_x", jsonrpc_machine_write_x_handler},
        {"machine.get_x_address", jsonrpc_machine_get_x_address_handler},
        {"machine.read_f", jsonrpc_machine_read_f_handler},
        {"machine.write_f", jsonrpc_machine_write_f_handler},
        {"machine.get_f_address", jsonrpc_machine_get_f_address_handler},
        {"machine.read_uarch_x", jsonrpc_machine_read_uarch_x_handler},
        {"machine.write_uarch_x", jsonrpc_machine_write_uarch_x_handler},
        {"machine.get_uarch_x_address", jsonrpc_machine_get_uarch_x_address_handler},
        {"machine.set_iflags_Y", jsonrpc_machine_set_iflags_Y_handler},
        {"machine.reset_iflags_Y", jsonrpc_machine_reset_iflags_Y_handler},
        {"machine.read_iflags_Y", jsonrpc_machine_read_iflags_Y_handler},
        {"machine.set_iflags_X", jsonrpc_machine_set_iflags_X_handler},
        {"machine.reset_iflags_X", jsonrpc_machine_reset_iflags_X_handler},
        {"machine.read_iflags_X", jsonrpc_machine_read_iflags_X_handler},
        {"machine.set_iflags_H", jsonrpc_machine_set_iflags_H_handler},
        {"machine.read_iflags_H", jsonrpc_machine_read_iflags_H_handler},
        {"machine.read_iflags_PRV", jsonrpc_machine_read_iflags_PRV_handler},
        {"machine.read_uarch_halt_flag", jsonrpc_machine_read_uarch_halt_flag_handler},
        {"machine.set_uarch_halt_flag", jsonrpc_machine_set_uarch_halt_flag_handler},
        {"machine.reset_uarch_state", jsonrpc_machine_reset_uarch_state_handler},
        {"machine.get_initial_config", jsonrpc_machine_get_initial_config_handler},
        {"machine.get_default_config", jsonrpc_machine_get_default_config_handler},
        {"machine.verify_merkle_tree", jsonrpc_machine_verify_merkle_tree_handler},
        {"machine.verify_dirty_page_maps", jsonrpc_machine_verify_dirty_page_maps_handler},
        {"machine.dump_pmas", jsonrpc_machine_dump_pmas_handler},
    };
    auto method = j["method"].get<std::string>();
    SLOG(debug) << h->server_address << " handling \"" << method << "\" method";
    auto found = dispatch.find(method);
    if (found != dispatch.end()) {
        return found->second(j, con, h);
    }
    return jsonrpc_response_method_not_found(j, method);
} catch (std::invalid_argument &x) {
    return jsonrpc_response_invalid_params(j, x.what());
} catch (std::exception &x) {
    return jsonrpc_response_internal_error(j, x.what());
}

/// \brief Handler for HTTP requests
/// \param con Mongoose connection
/// \param ev Mongoose event
/// \param ev_data Mongoose event data
/// \param h_data Handler data
static void http_handler(mg_connection *con, int ev, void *ev_data, void *h_data) {
    auto *h = static_cast<http_handler_data *>(h_data);
    if (ev == MG_EV_HTTP_MSG) {
        auto *hm = static_cast<mg_http_message *>(ev_data);
        const std::string_view method{hm->method.ptr, hm->method.len};
        // Answer OPTIONS request to support cross origin resource sharing (CORS) preflighted browser requests
        if (method == "OPTIONS") {
            SLOG(trace) << h->server_address << " serving \"" << method << "\" request";
            std::string headers;
            headers += "Access-Control-Allow-Origin: *\r\n";
            headers += "Access-Control-Allow-Methods: *\r\n";
            headers += "Access-Control-Allow-Headers: *\r\n";
            headers += "Access-Control-Max-Age: 0\r\n";
            mg_http_reply(con, 204, headers.c_str(), "");
            return;
        }
        // Only accept POST requests
        if (method != "POST") {
            std::string headers;
            headers += "Access-Control-Allow-Origin: *\r\n";
            SLOG(trace) << h->server_address << " rejected unexpected \"" << method << "\" request";
            mg_http_reply(con, 405, headers.c_str(), "method not allowed");
            return;
        }
        // Only accept / URI
        const std::string_view uri{hm->uri.ptr, hm->uri.len};
        SLOG(trace) << h->server_address << " request is " << std::string_view{hm->body.ptr, hm->body.len};
        if (uri != "/") {
            // anything else
            SLOG(trace) << h->server_address << " rejected unexpected \"" << uri << "\" uri";
            mg_http_reply(con, 404, "Access-Control-Allow-Origin: *\r\n", "not found");
            return;
        }
        // Parse request body into a JSON object
        json j;
        try {
            j = json::parse(hm->body.ptr, hm->body.ptr + hm->body.len);
        } catch (std::exception &x) {
            return jsonrpc_http_reply(con, h, jsonrpc_response_parse_error(x.what()));
        }
        // JSONRPC allows batch requests, each an entry in an array
        // We deal uniformly with batch and singleton requests by wrapping the singleton into a batch
        auto was_array = j.is_array();
        if (!was_array) {
            j = json::array({std::move(j)});
        }
        if (j.empty()) {
            return jsonrpc_http_reply(con, h, jsonrpc_response_invalid_request(j, "empty batch request array"));
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
                jr.push_back(
                    jsonrpc_response_invalid_request(ji, "invalid field \"method\" (expected non-empty string)"));
                continue;
            }
            // check for valid id
            if (ji.contains("id")) {
                const auto &jiid = ji["id"];
                if (!jiid.is_string() && !jiid.is_number() && !jiid.is_null()) {
                    jr.push_back(jsonrpc_response_invalid_request(ji,
                        "invalid field \"id\" (expected string, number, or null)"));
                }
            }
            json jri = jsonrpc_dispatch_method(ji, con, h);
            if (h->status == http_handler_status::forked_child) {
                return;
            }
            // Except for errors, do not add result of "notification" requests
            if (ji.contains("id")) {
                jr.push_back(std::move(jri));
            }
        }
        // Unwrap singleton request from batch, if it was indeed a singleton
        // Otherwise, just send the response
        if (!jr.empty()) {
            if (was_array) {
                return jsonrpc_http_reply(con, h, jr);
            }
            return jsonrpc_http_reply(con, h, jr[0]);
        }
        return jsonrpc_send_empty_reply(con, h);
    }
    if (ev == MG_EV_CLOSE) {
        if (con->data[0] == 'X') {
            h->status = http_handler_status::shutdown;
            return;
        }
    }
    if (ev == MG_EV_ERROR) {
        SLOG(debug) << h->server_address << " " << static_cast<char *>(ev_data);
        return;
    }
}

/// \brief Prints help message
/// \param name Executable name
static void help(const char *name) {
    (void) fprintf(stderr,
        R"(Usage:

    %s [options] [<server-address>]

where

    --server-address=<server-address> or [<server-address>]
      gives the address of the server
      <server-address> can be
        <ipv4-hostname/address>:<port>
        <ipv6-hostname/address>:<port>
      when <port> is 0, an ephemeral port will be automatically selected
      default is "localhost:0"

and options are

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
    const char *server_address = "localhost:0";
    const char *log_level = nullptr;
    const char *program_name = PROGRAM_NAME;

    if (argc > 0) { // NOLINT: of course it could be == 0...
        program_name = argv[0];
    }

    for (int i = 1; i < argc; i++) {
        if (stringval("--server-address=", argv[i], &server_address)) {
            ;
        } else if (stringval("--log-level=", argv[i], &log_level)) {
            ;
        } else if (strcmp(argv[i], "--help") == 0) {
            help(program_name);
            exit(0);
        } else {
            if (!server_address) {
                server_address = argv[i];
            } else {
                std::cerr << "repeated [<server-address>] option";
                exit(1);
            }
        }
    }

    init_logger(log_level);

    SLOG(info) << "server version is " << server_version_major << "." << server_version_minor << "."
               << server_version_patch;

    SLOG(info) << "'" << server_address << "' requested as initial server address";

    install_signal_handlers();

    http_handler_data *h = new (std::nothrow) http_handler_data{};
    if (!h) {
        SLOG(fatal) << "out of memory";
        exit(1);
    }

    mg_mgr_init(&h->event_manager);
#if MG_ENABLE_EPOLL
    // Event manager initialization does not return whether it failed or not
    // It could only fail if the epoll_fd allocation failed
    if (h->event_manager.epoll_fd < 0) {
        mg_mgr_free(&h->event_manager);
        delete h;
        SLOG(fatal) << "failed creating event manager";
        exit(1);
    }
#endif

    const auto *con = mg_http_listen(&h->event_manager, server_address, http_handler, h);
    if (!con) {
        mg_mgr_free(&h->event_manager);
        delete h;
        SLOG(fatal) << "failed listening";
        exit(1);
    }
    h->server_address = server_address;

    SLOG(info) << "initial server bound to port " << ntohs(con->loc.port);

    while (!abort_due_to_signal) {
        log_signals();
        h->status = http_handler_status::ready_for_next;
        mg_mgr_poll(&h->event_manager, 10000);
        switch (h->status) {
            case http_handler_status::shutdown:
                mg_mgr_free(&h->event_manager);
                delete h;
                return 0;
            case http_handler_status::forked_child: {
                // The child doesn't need the old server it inherited from the parent.
                // So we release it and make the new one current.
                http_handler_data *old_h = h;
                mg_mgr_free_ours(&h->event_manager);
                h = h->child;
                delete old_h;
                break;
            }
            case http_handler_status::ready_for_next:
            default:
                break;
        }
    }
    log_signals();
    mg_mgr_free(&h->event_manager);
    delete h;
    return 0;
} catch (std::exception &e) {
    std::cerr << "Caught exception: " << e.what() << '\n';
    return 1;
} catch (...) {
    std::cerr << "Caught unknown exception\n";
    return 1;
}
