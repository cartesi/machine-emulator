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

#include "jsonrpc-machine-c-api.h"
#include "i-virtual-machine.h"
#include "json-util.h"
#include "jsonrpc-connection.h"
#include "jsonrpc-virtual-machine.h"
#include "machine-c-api-internal.h"
#include "os-features.h"

static const cartesi::jsonrpc_connection_ptr *convert_from_c(const cm_jsonrpc_connection *con) {
    if (con == nullptr) {
        throw std::invalid_argument("invalid stub");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const cartesi::jsonrpc_connection_ptr *>(con);
}

cm_error cm_jsonrpc_create_connection(const char *remote_address, cm_jsonrpc_connection **con) try {
    if (con == nullptr) {
        throw std::invalid_argument("invalid stub output");
    }
    auto *cpp_connection = new std::shared_ptr<cartesi::jsonrpc_connection>(
        new cartesi::jsonrpc_connection{remote_address ? remote_address : ""});
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *con = reinterpret_cast<cm_jsonrpc_connection *>(cpp_connection);
    return cm_result_success();
} catch (...) {
    if (con) {
        *con = nullptr;
    }
    return cm_result_failure();
}

void cm_jsonrpc_destroy_connection(const cm_jsonrpc_connection *con) {
    if (con == nullptr) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *mgr_wrapper = reinterpret_cast<const cartesi::jsonrpc_connection_ptr *>(con);
    delete mgr_wrapper;
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

cm_error cm_jsonrpc_shutdown(const cm_jsonrpc_connection *con) try {
    const auto *cpp_connection = convert_from_c(con);
    cartesi::jsonrpc_virtual_machine::shutdown(*cpp_connection);
    return cm_result_success();
} catch (...) {
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
