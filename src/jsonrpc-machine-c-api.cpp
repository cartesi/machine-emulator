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
#include <stdexcept>
#include <string>

#include "access-log.h"
#include "i-virtual-machine.h"
#include "json-util.h"
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

using namespace std::string_literals;

static cartesi::jsonrpc_virtual_machine::cleanup_call convert_from_c(cm_jsonrpc_cleanup_call call) {
    switch (call) {
        case CM_JSONRPC_DESTROY:
            return cartesi::jsonrpc_virtual_machine::cleanup_call::destroy;
        case CM_JSONRPC_SHUTDOWN:
            return cartesi::jsonrpc_virtual_machine::cleanup_call::shutdown;
        case CM_JSONRPC_NOTHING:
            return cartesi::jsonrpc_virtual_machine::cleanup_call::nothing;
        default:
            throw std::invalid_argument("invalid cleanup call");
    }
}

static cm_jsonrpc_cleanup_call convert_to_c(cartesi::jsonrpc_virtual_machine::cleanup_call call) {
    switch (call) {
        case cartesi::jsonrpc_virtual_machine::cleanup_call::destroy:
            return CM_JSONRPC_DESTROY;
        case cartesi::jsonrpc_virtual_machine::cleanup_call::shutdown:
            return CM_JSONRPC_SHUTDOWN;
        case cartesi::jsonrpc_virtual_machine::cleanup_call::nothing:
            return CM_JSONRPC_NOTHING;
        default:
            throw std::invalid_argument("invalid cleanup call");
    }
}

static cartesi::jsonrpc_virtual_machine *convert_from_c(cm_machine *m) {
    if (m == nullptr) {
        throw std::invalid_argument("invalid machine");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *cpp_m = reinterpret_cast<cartesi::i_virtual_machine *>(m);
    if (!cpp_m->is_jsonrpc_virtual_machine()) {
        throw std::invalid_argument("not a JSONRPC remote machine");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cartesi::jsonrpc_virtual_machine *>(m);
}

static const cartesi::jsonrpc_virtual_machine *convert_from_c(const cm_machine *m) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    return convert_from_c(const_cast<cm_machine *>(m));
}

static cm_machine *convert_to_c(cartesi::i_virtual_machine *cpp_m) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cm_machine *>(cpp_m);
}

cm_error cm_jsonrpc_connect_server(const char *address, int64_t connect_timeout_ms, cm_machine **new_m) try {
    using namespace cartesi;
    if (address == nullptr) {
        throw std::invalid_argument("invalid address");
    }
    if (new_m == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    *new_m = convert_to_c(new jsonrpc_virtual_machine(address, connect_timeout_ms));
    return cm_result_success();
} catch (...) {
    if (new_m != nullptr) {
        *new_m = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_spawn_server(const char *address, int64_t spawn_timeout_ms, cm_machine **new_m,
    const char **bound_address, uint32_t *pid) try {
    using namespace cartesi;
    if (address == nullptr) {
        throw std::invalid_argument("invalid address");
    }
    if (new_m == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    fork_result spawned;
    *new_m = convert_to_c(new jsonrpc_virtual_machine(address, spawn_timeout_ms, spawned));
    if (bound_address != nullptr) {
        *bound_address = cm_set_temp_string(spawned.address);
    }
    if (pid != nullptr) {
        *pid = spawned.pid;
    }
    return cm_result_success();
} catch (...) {
    if (new_m != nullptr) {
        *new_m = nullptr;
    }
    if (bound_address != nullptr) {
        *bound_address = nullptr;
    }
    if (pid != nullptr) {
        *pid = 0;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_fork_server(const cm_machine *m, cm_machine **forked_m, const char **address, uint32_t *pid) try {
    using namespace cartesi;
    if (address == nullptr) {
        throw std::invalid_argument("invalid address output");
    }
    const auto *cpp_m = convert_from_c(m);
    const auto forked = cpp_m->fork_server();
    *address = cm_set_temp_string(forked.address);
    if (pid != nullptr) {
        *pid = static_cast<int>(forked.pid);
    }
    auto *cpp_forked_m = new jsonrpc_virtual_machine(forked.address);
    cpp_forked_m->set_cleanup_call(cpp_m->get_cleanup_call());
    cpp_forked_m->set_timeout(cpp_m->get_timeout());
    *forked_m = convert_to_c(cpp_forked_m);
    return cm_result_success();
} catch (...) {
    if (address != nullptr) {
        *address = nullptr;
    }
    if (pid != nullptr) {
        *pid = 0;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_rebind_server(cm_machine *m, const char *address, const char **address_bound) try {
    auto *cpp_m = convert_from_c(m);
    const auto cpp_address_bound = cpp_m->rebind_server(address);
    if (address_bound != nullptr) {
        *address_bound = cm_set_temp_string(cpp_address_bound);
    }
    return cm_result_success();
} catch (...) {
    if (address_bound != nullptr) {
        *address_bound = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_server_version(const cm_machine *m, const char **version) try {
    if (version == nullptr) {
        throw std::invalid_argument("invalid version output");
    }
    const auto *cpp_m = convert_from_c(m);
    const auto cpp_version = cpp_m->get_server_version();
    *version = cm_set_temp_string(cartesi::to_json(cpp_version).dump());
    return cm_result_success();
} catch (...) {
    if (version != nullptr) {
        *version = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_jsonrpc_shutdown_server(cm_machine *m) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->shutdown_server();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_delay_next_request(cm_machine *m, uint64_t ms) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->delay_next_request(ms);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_set_timeout(cm_machine *m, int64_t ms) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->set_timeout(ms);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_timeout(cm_machine *m, int64_t *ms) try {
    if (ms == nullptr) {
        throw std::invalid_argument("invalid ms output");
    }
    auto *cpp_m = convert_from_c(m);
    *ms = cpp_m->get_timeout();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_set_cleanup_call(cm_machine *m, cm_jsonrpc_cleanup_call call) try {
    auto *cpp_m = convert_from_c(m);
    auto cpp_call = convert_from_c(call);
    cpp_m->set_cleanup_call(cpp_call);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_cleanup_call(cm_machine *m, cm_jsonrpc_cleanup_call *call) try {
    if (call == nullptr) {
        throw std::invalid_argument("invalid call output");
    }
    auto *cpp_m = convert_from_c(m);
    *call = convert_to_c(cpp_m->get_cleanup_call());
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_get_server_address(cm_machine *m, const char **address) try {
    if (address == nullptr) {
        throw std::invalid_argument("invalid address output");
    }
    auto *cpp_m = convert_from_c(m);
    *address = cm_set_temp_string(cpp_m->get_server_address());
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_jsonrpc_emancipate_server(cm_machine *m) try {
    auto *cpp_m = convert_from_c(m);
    cpp_m->emancipate_server();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}
