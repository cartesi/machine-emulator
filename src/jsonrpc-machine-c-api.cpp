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
#include "os.h"
#include "semantic-version.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "asio-config.h"
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#pragma GCC diagnostic pop

using namespace std::string_literals;

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

cm_error cm_jsonrpc_connect(const char *address, int detach_server, cm_jsonrpc_connection **con) try {
    if (address == nullptr) {
        throw std::invalid_argument("invalid address");
    }
    if (con == nullptr) {
        throw std::invalid_argument("invalid connection output");
    }
    auto *cpp_con =
        new cartesi::jsonrpc_connection_ptr(std::make_shared<cartesi::jsonrpc_connection>(address, detach_server));
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

cm_error cm_jsonrpc_spawn_server(const char *address, int detach_server, cm_jsonrpc_connection **con,
    const char **bound_address, int32_t *pid) try {
    // this function first blocks SIGUSR1, SIGUSR2 and SIGALRM.
    // then it double-forks.
    // the grand-child sends the parent a SIGUSR2 and suicides if failed before execing jsonrpc-remote-cartesi-machine.
    // otherwise, jsonrpc-remote-cartesi-machine itself sends the parent a SIGUSR1 to notify it is ready.
    // the parent sets up to receive a SIGALRM after 15 seconds and then waits for SIGUSR1, SIGUSR2 or SIGALRM
    // if it gets SIGALRM, the grand-child is unresponsive, so the parent kills it and cm_jsonrpc_spawn fails.
    // if it gets SIGUSR2, the grand-child failed before exec and suicided, so cm_jsonrpc_spawn fails.
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
    boost::asio::io_context ioc{1};
    boost::asio::ip::tcp::acceptor a(ioc, address_to_endpoint(address));
    // already done by constructor
    // a.open(endpoint.protocol());
    // a.set_option(asio::socket_base::reuse_address(true));
    // a.bind(endpoint);
    // a.listen(asio::socket_base::max_listen_connections);
    const char *bin = getenv("JSONRPC_REMOTE_CARTESI_MACHINE");
    if (!bin) {
        bin = "jsonrpc-remote-cartesi-machine";
    }
    auto ppid = getpid();
    bool restore_grand_child = false;
    const int32_t grand_child = cartesi::os_double_fork_or_throw(true);
    if (grand_child == 0) { // grand-child and double-fork() succeeded
        sigprocmask(SIG_SETMASK, &omask, nullptr);
        char sigusr1[256] = "";
        (void) snprintf(sigusr1, std::size(sigusr1), "--sigusr1=%d", ppid);
        char server_fd[256] = "";
        (void) snprintf(server_fd, std::size(server_fd), "--server-fd=%d", a.native_handle());
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        char *args[] = {const_cast<char *>(bin), server_fd, sigusr1, nullptr};
        if (execvp(bin, args) < 0) {
            // here we failed to run jsonrpc-remote-cartesi-machine. nothing we can do.
            kill(ppid, SIGUSR2); // notify parent as soon as possible that we failed.
            exit(1);
        };
        return cm_result_success(); // code never reaches here
    } else if (grand_child > 0) {   // parent and double-fork() succeeded
        restore_grand_child = true; // make sure grand-child is killed if we fail
        static THREAD_LOCAL std::string bound_address_storage = endpoint_to_string(a.local_endpoint());
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
            *bound_address = bound_address_storage.c_str();
            *pid = grand_child;
            auto ret = cm_jsonrpc_connect(*bound_address, detach_server, con);
            if (ret < 0) { // and yet we failed to connect
                kill(grand_child, SIGTERM);
                *bound_address = nullptr;
                *pid = 0;
            }
            return ret;
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
            *con = nullptr;
            *bound_address = nullptr;
            *pid = 0;
            return cm_result_failure();
        }
    }
    return cm_result_success(); // code never reaches here
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

cm_error cm_jsonrpc_create_machine(const cm_jsonrpc_connection *con, int detach_machine, const char *config,
    const char *runtime_config, cm_machine **new_machine) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const cartesi::machine_config c = cartesi::from_json<cartesi::machine_config>(config);
    cartesi::machine_runtime_config r;
    if (runtime_config) {
        r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config);
    }
    const auto *cpp_con = convert_from_c(con);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine =
        reinterpret_cast<cm_machine *>(new cartesi::jsonrpc_virtual_machine(*cpp_con, detach_machine, c, r));
    return cm_result_success();
} catch (...) {
    if (new_machine) {
        *new_machine = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_load_machine(const cm_jsonrpc_connection *con, int detach_machine, const char *dir,
    const char *runtime_config, cm_machine **new_machine) try {
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
    const auto *cpp_con = convert_from_c(con);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine =
        reinterpret_cast<cm_machine *>(new cartesi::jsonrpc_virtual_machine(*cpp_con, detach_machine, dir, r));
    return cm_result_success();
} catch (...) {
    if (new_machine) {
        *new_machine = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_machine(const cm_jsonrpc_connection *con, int detach_machine, cm_machine **new_machine) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const auto *cpp_con = convert_from_c(con);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(new cartesi::jsonrpc_virtual_machine(*cpp_con, detach_machine));
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
    const auto *cpp_con = convert_from_c(con);
    const cartesi::machine_config cpp_config = cartesi::jsonrpc_virtual_machine::get_default_config(*cpp_con);
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
    const auto *cpp_con = convert_from_c(con);
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log).value();
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::jsonrpc_virtual_machine::verify_step_uarch(*cpp_con, cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_verify_reset_uarch(const cm_jsonrpc_connection *con, const cm_hash *root_hash_before,
    const char *log, const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto *cpp_con = convert_from_c(con);
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log).value();
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::jsonrpc_virtual_machine::verify_reset_uarch(*cpp_con, cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_fork_server(const cm_jsonrpc_connection *con, const char **address, int32_t *pid) try {
    if (address == nullptr) {
        throw std::invalid_argument("invalid address output");
    }
    const auto *cpp_con = convert_from_c(con);
    const auto result = (*cpp_con)->fork_server();
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

cm_error cm_jsonrpc_rebind_server(const cm_jsonrpc_connection *con, const char *address, const char **new_address) try {
    const auto *cpp_con = convert_from_c(con);
    const std::string cpp_new_address = (*cpp_con)->rebind_server(address);
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
    const auto *cpp_con = convert_from_c(con);
    const auto cpp_reg = static_cast<cartesi::machine::reg>(reg);
    *val = cartesi::jsonrpc_virtual_machine::get_reg_address(*cpp_con, cpp_reg);
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_server_version(const cm_jsonrpc_connection *con, const char **version) try {
    if (version == nullptr) {
        throw std::invalid_argument("invalid version output");
    }
    const auto *cpp_con = convert_from_c(con);
    const cartesi::semantic_version cpp_version = (*cpp_con)->get_server_version();
    *version = cm_set_temp_string(cartesi::to_json(cpp_version).dump());
    return cm_result_success();
} catch (...) {
    if (version) {
        *version = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_shutdown_server(const cm_jsonrpc_connection *con) try {
    const auto *cpp_con = convert_from_c(con);
    (*cpp_con)->shutdown_server();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_verify_send_cmio_response(const cm_jsonrpc_connection *con, uint16_t reason, const uint8_t *data,
    uint64_t length, const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto *cpp_con = convert_from_c(con);
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log).value();
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::jsonrpc_virtual_machine::verify_send_cmio_response(*cpp_con, reason, data, length, cpp_root_hash_before,
        cpp_log, cpp_root_hash_after);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}
