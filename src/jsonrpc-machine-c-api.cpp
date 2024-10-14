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

#include <cassert>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/time.h>
#include <system_error>
#include <unistd.h>

#include "access-log.h"
#include "i-virtual-machine.h"
#include "json-util.h"
#include "jsonrpc-connection.h"
#include "jsonrpc-machine-c-api.h"
#include "jsonrpc-virtual-machine.h"
#include "machine-c-api-internal.h"
#include "machine-c-api.h"
#include "machine-config.h"
#include "machine-runtime-config.h"
#include "machine.h"
#include "os-features.h"
#include "semantic-version.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "asio-config.h"
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#pragma GCC diagnostic pop

using namespace std::string_literals;

cartesi::jsonrpc_connection::manage convert_from_c(cm_jsonrpc_manage what) {
    switch (what) {
        case CM_JSONRPC_MANAGE_SERVER:
            return cartesi::jsonrpc_connection::manage::server;
        case CM_JSONRPC_MANAGE_MACHINE:
            return cartesi::jsonrpc_connection::manage::machine;
        case CM_JSONRPC_MANAGE_NONE:
            return cartesi::jsonrpc_connection::manage::none;
        default:
            throw std::domain_error("invalid cm_jsonrpc_manage");
            return cartesi::jsonrpc_connection::manage::server;
    }
}

static const cartesi::jsonrpc_connection_ptr *convert_from_c(const cm_jsonrpc_connection *con) {
    if (con == nullptr) {
        throw std::invalid_argument("invalid connection");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const cartesi::jsonrpc_connection_ptr *>(con);
}

static cartesi::i_virtual_machine *convert_from_c(cm_machine *m) {
    if (m == nullptr) {
        throw std::invalid_argument("invalid machine");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cartesi::i_virtual_machine *>(m);
}

cm_error cm_jsonrpc_connect(const char *address, cm_jsonrpc_manage what, cm_jsonrpc_connection **con) try {
    if (address == nullptr) {
        throw std::invalid_argument("invalid address");
    }
    if (con == nullptr) {
        throw std::invalid_argument("invalid connection output");
    }
    auto cpp_what = convert_from_c(what);
    auto *cpp_con =
        new cartesi::jsonrpc_connection_ptr(std::make_shared<cartesi::jsonrpc_connection>(address, cpp_what));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *con = reinterpret_cast<cm_jsonrpc_connection *>(cpp_con);
    return cm_result_success();
} catch (...) {
    if (con) {
        *con = nullptr;
    }
    return cm_result_failure();
}

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

cm_error cm_jsonrpc_spawn(const char *address, cm_jsonrpc_manage what, cm_jsonrpc_connection **con,
    const char **bound_address, int32_t *pid) try {
    // this function first blocks SIGUSR1, SIGUSR2 and SIGALRM.
    // then it forks.
    // the child sends the parent a SIGUSR2 and suicides if failed before execing jsonrpc-remote-cartesi-machine.
    // otherwise, jsonrpc-remote-cartesi-machine sends the parent a SIGUSR1 to notify it is ready.
    // the parent sets up to receive a SIGALRM after 15 seconds and then waits for SIGUSR1, SIGUSR2 or SIGALRM
    // if it gets SIGALRM, the child is unresponsive and he parent kills and cm_jsonrpc_spawn fails.
    // if it gets SIGUSR2, the child failed before exec an suicided, so cm_jsonrpc_spawn fails.
    // if it gets SIGUSR1, jsonrpc-remote-cartesi-machine is ready and cm_jsonrpc_span succeeds.
    if (address == nullptr) {
        throw std::invalid_argument("invalid address");
    }
    if (con == nullptr) {
        throw std::invalid_argument("invalid connection output");
    }
    if (bound_address == nullptr) {
        throw std::invalid_argument("invalid bound address output");
    }
    if (pid == nullptr) {
        throw std::invalid_argument("invalid pid output");
    }
    boost::asio::io_context ioc{1};
    boost::asio::ip::tcp::acceptor a(ioc, address_to_endpoint(address));
    // already done by constructor
    // a.open(endpoint.protocol());
    // a.set_option(asio::socket_base::reuse_address(true));
    // a.bind(endpoint);
    // a.listen(asio::socket_base::max_listen_connections);
    static THREAD_LOCAL std::string bound_address_storage = endpoint_to_string(a.local_endpoint());
    sigset_t mask{};
    sigset_t omask{};
    sigemptyset(&mask);        // always returns 0
    sigaddset(&mask, SIGUSR1); // always returns 0
    sigaddset(&mask, SIGUSR2); // always returns 0
    sigaddset(&mask, SIGALRM); // always returns 0
    if (sigprocmask(SIG_BLOCK, &mask, &omask) < 0) {
        // sigprocmask can only fail if we screwed up the values. this can't happen.
        // being paranoid, if it *did* happen, we are trying to avoid a situation where
        // our process gets killed when the child or the alarm tries to signal us
        throw std::system_error{errno, std::generic_category(), "sigprocmask failed"};
    }
    const char *bin = getenv("JSONRPC_REMOTE_CARTESI_MACHINE");
    if (!bin) {
        bin = "jsonrpc-remote-cartesi-machine";
    }
    const int32_t child = fork();
    if (child == 0) { // child
        sigprocmask(SIG_SETMASK, &omask, nullptr);
        char server_fd[256] = "";
        (void) snprintf(server_fd, std::size(server_fd), "--server-fd=%d", a.native_handle());
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        char *args[] = {const_cast<char *>(bin), server_fd, const_cast<char *>("--setpgid"),
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            const_cast<char *>("--sigusr1"), nullptr};
        if (execvp(bin, args) < 0) {
            // here we failed to run jsonrpc-remote-cartesi-machine. nothing we can do.
            kill(getppid(), SIGUSR2); // notify parent we failed
            exit(1);
        };
        return cm_result_success(); // code never reaches here
    } else if (child > 0) {         // parent and fork() succeeded
        // get rid of our copy of socket
        a.close();
        // change child to its own process group
        if (setpgid(child, child) < 0) {
            // we don't want to be in a situation where the child is in the parent's process group.
            // otherwise, should the client then kill the process group, it would be committing suicide...
            kill(child, SIGTERM); // we try to kill the poor child
            waitpid(child, nullptr, WNOHANG);
            throw std::system_error{errno, std::generic_category(), "setpgid failed"};
        }
        struct itimerval value {};
        memset(&value, 0, sizeof(value));
        value.it_interval.tv_sec = 0;
        value.it_interval.tv_usec = 0;
        value.it_value.tv_sec = 15;
        value.it_value.tv_usec = 0;
        struct itimerval ovalue {};
        memset(&ovalue, 0, sizeof(ovalue));
        if (setitimer(ITIMER_REAL, &value, &ovalue) < 0) {
            // setitimer only fails if we screwed up with the values. this should not happen.
            // being paranoid, if it *did* happen, and if the child also failed to signal us,
            // we might hang forever in the following call to sigwait.
            // we prefer to give up instead of risking a deadlock.
            kill(child, SIGTERM); // we try to kill the poor child
            waitpid(child, nullptr, WNOHANG);
            sigprocmask(SIG_SETMASK, &omask, nullptr); // we try to restore our mask
            throw std::system_error{errno, std::generic_category(), "setitimer failed"};
        }
        int sig = 0;
        if (auto ret = sigwait(&mask, &sig); ret != 0) {
            // here sigwait failed.
            kill(child, SIGTERM); // we try to kill the poor child
            waitpid(child, nullptr, WNOHANG);
            sigprocmask(SIG_SETMASK, &omask, nullptr); // we try to restore our mask
            setitimer(ITIMER_REAL, &ovalue, nullptr);  // we try to restore the timer
            throw std::system_error{ret, std::generic_category(), "sigwait failed"};
        }
        // restore previous timer
        setitimer(ITIMER_REAL, &ovalue, nullptr);
        sigprocmask(SIG_SETMASK, &omask, nullptr);
        if (sig == SIGALRM) { // child didn't signal us before alarm
            kill(child, SIGTERM);
            waitpid(child, nullptr, WNOHANG);
            throw std::runtime_error{"child process unresponsive"};
        }
        if (sig == SIGUSR2) { // child signaled us that it failed to exec
            // child will have exited on its own
            waitpid(child, nullptr, WNOHANG);
            throw std::runtime_error{"failed to run '"s + bin + "'"s};
        }
        assert(sig == SIGUSR1);
        // child signaled us that everything is fine
        *bound_address = bound_address_storage.c_str();
        *pid = child;
        auto ret = cm_jsonrpc_connect(*bound_address, what, con);
        if (ret < 0) { // and yet we failed to connect
            kill(child, SIGTERM);
            waitpid(child, nullptr, WNOHANG);
            *bound_address = nullptr;
            *pid = 0;
        }
        return ret;
    } else { // fork failed
        throw std::system_error{errno, std::generic_category(), "fork failed"};
    }
} catch (...) {
    *con = nullptr;
    *bound_address = nullptr;
    *pid = 0;
    return cm_result_failure();
}

void cm_jsonrpc_release_connection(const cm_jsonrpc_connection *con) {
    if (con == nullptr) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *cpp_con = reinterpret_cast<const cartesi::jsonrpc_connection_ptr *>(con);
    delete cpp_con;
}

cm_error cm_jsonrpc_create_machine(const cm_jsonrpc_connection *con, const char *config, const char *runtime_config,
    cm_machine **new_machine) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const cartesi::machine_config c = cartesi::from_json<cartesi::machine_config>(config);
    cartesi::machine_runtime_config r;
    if (runtime_config) {
        r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config);
    }
    const auto *cpp_connection = convert_from_c(con);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(new cartesi::jsonrpc_virtual_machine(*cpp_connection, c, r));
    return cm_result_success();
} catch (...) {
    if (new_machine) {
        *new_machine = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_load_machine(const cm_jsonrpc_connection *con, const char *dir, const char *runtime_config,
    cm_machine **new_machine) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    if (dir == nullptr) {
        throw std::invalid_argument("invalid dir");
    }
    cartesi::machine_runtime_config r;
    if (runtime_config) {
        r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config);
    }
    const auto *cpp_connection = convert_from_c(con);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(new cartesi::jsonrpc_virtual_machine(*cpp_connection, dir, r));
    return cm_result_success();
} catch (...) {
    if (new_machine) {
        *new_machine = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_machine(const cm_jsonrpc_connection *con, cm_machine **new_machine) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const auto *cpp_connection = convert_from_c(con);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(new cartesi::jsonrpc_virtual_machine(*cpp_connection));
    return cm_result_success();
} catch (...) {
    if (new_machine) {
        *new_machine = nullptr;
    }
    return cm_result_failure();
}

CM_API cm_error cm_jsonrpc_get_connection(cm_machine *m, const cm_jsonrpc_connection **con) try {
    auto *cpp_machine = convert_from_c(m);
    cartesi::jsonrpc_virtual_machine *cpp_json_machine = dynamic_cast<cartesi::jsonrpc_virtual_machine *>(cpp_machine);
    if (!cpp_json_machine) {
        throw std::invalid_argument("not a remote machine");
    }
    auto *cpp_con = new cartesi::jsonrpc_connection_ptr(cpp_json_machine->get_connection());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *con = reinterpret_cast<cm_jsonrpc_connection *>(cpp_con);
    return cm_result_success();
} catch (...) {
    *con = nullptr;
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_default_config(const cm_jsonrpc_connection *con, const char **config) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    const auto *cpp_connection = convert_from_c(con);
    const cartesi::machine_config cpp_config = cartesi::jsonrpc_virtual_machine::get_default_config(*cpp_connection);
    *config = cm_set_temp_string(cartesi::to_json(cpp_config).dump());
    return cm_result_success();
} catch (...) {
    if (config) {
        *config = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_verify_step_uarch(const cm_jsonrpc_connection *con, const cm_hash *root_hash_before,
    const char *log, const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto *cpp_connection = convert_from_c(con);
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log).value();
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::jsonrpc_virtual_machine::verify_step_uarch(*cpp_connection, cpp_root_hash_before, cpp_log,
        cpp_root_hash_after);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_verify_reset_uarch(const cm_jsonrpc_connection *con, const cm_hash *root_hash_before,
    const char *log, const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto *cpp_connection = convert_from_c(con);
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log).value();
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::jsonrpc_virtual_machine::verify_reset_uarch(*cpp_connection, cpp_root_hash_before, cpp_log,
        cpp_root_hash_after);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_fork(const cm_jsonrpc_connection *con, const char **address, int32_t *pid) try {
    if (address == nullptr) {
        throw std::invalid_argument("invalid address output");
    }
    const auto *cpp_connection = convert_from_c(con);
    const auto result = cartesi::jsonrpc_virtual_machine::fork(*cpp_connection);
    *address = cm_set_temp_string(result.address);
    if (pid) {
        *pid = static_cast<int>(result.pid);
    }
    return cm_result_success();
} catch (...) {
    if (address) {
        *address = nullptr;
    }
    if (pid) {
        *pid = 0;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_rebind(const cm_jsonrpc_connection *con, const char *address, const char **new_address) try {
    const auto *cpp_connection = convert_from_c(con);
    const std::string cpp_new_address = cartesi::jsonrpc_virtual_machine::rebind(*cpp_connection, address);
    if (new_address) {
        *new_address = cm_set_temp_string(cpp_new_address);
    }
    return cm_result_success();
} catch (...) {
    if (new_address) {
        *new_address = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_reg_address(const cm_jsonrpc_connection *con, cm_reg reg, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_connection = convert_from_c(con);
    const auto cpp_reg = static_cast<cartesi::machine::reg>(reg);
    *val = cartesi::jsonrpc_virtual_machine::get_reg_address(*cpp_connection, cpp_reg);
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_version(const cm_jsonrpc_connection *con, const char **version) try {
    if (version == nullptr) {
        throw std::invalid_argument("invalid version output");
    }
    const auto *cpp_connection = convert_from_c(con);
    const cartesi::semantic_version cpp_version = cartesi::jsonrpc_virtual_machine::get_version(*cpp_connection);
    *version = cm_set_temp_string(cartesi::to_json(cpp_version).dump());
    return cm_result_success();
} catch (...) {
    if (version) {
        *version = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_verify_send_cmio_response(const cm_jsonrpc_connection *con, uint16_t reason, const uint8_t *data,
    uint64_t length, const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto *cpp_connection = convert_from_c(con);
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log).value();
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::jsonrpc_virtual_machine::verify_send_cmio_response(*cpp_connection, reason, data, length,
        cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}
