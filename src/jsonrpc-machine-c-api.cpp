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
#include "jsonrpc-mgr.h"
#include "jsonrpc-virtual-machine.h"
#include "machine-c-api-internal.h"
#include "os-features.h"

static const cartesi::jsonrpc_mgr_ptr *convert_from_c(const cm_jsonrpc_mgr *mgr) {
    if (mgr == nullptr) {
        throw std::invalid_argument("invalid stub");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const cartesi::jsonrpc_mgr_ptr *>(mgr);
}

static inline cartesi::i_virtual_machine *create_jsonrpc_virtual_machine(const cartesi::jsonrpc_mgr_ptr &mgr,
    const cartesi::machine_config &c, const cartesi::machine_runtime_config &r) {
    return new cartesi::jsonrpc_virtual_machine(mgr, c, r);
}

static inline cartesi::i_virtual_machine *load_jsonrpc_virtual_machine(const cartesi::jsonrpc_mgr_ptr &mgr,
    const char *dir, const cartesi::machine_runtime_config &r) {
    return new cartesi::jsonrpc_virtual_machine(mgr, null_to_empty(dir), r);
}

static inline cartesi::i_virtual_machine *get_jsonrpc_virtual_machine(const cartesi::jsonrpc_mgr_ptr &mgr) {
    return new cartesi::jsonrpc_virtual_machine(mgr);
}

int cm_jsonrpc_create_mgr(const char *remote_address, cm_jsonrpc_mgr **mgr) try {
    if (mgr == nullptr) {
        throw std::invalid_argument("invalid stub output");
    }
    auto *cpp_mgr = new std::shared_ptr<cartesi::jsonrpc_mgr>(new cartesi::jsonrpc_mgr{null_to_empty(remote_address)});
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *mgr = reinterpret_cast<cm_jsonrpc_mgr *>(cpp_mgr);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

void cm_jsonrpc_destroy_mgr(const cm_jsonrpc_mgr *mgr) {
    if (mgr == nullptr) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *mgr_wrapper = reinterpret_cast<const cartesi::jsonrpc_mgr_ptr *>(mgr);
    delete mgr_wrapper;
}

int cm_jsonrpc_create_machine(const cm_jsonrpc_mgr *mgr, const char *config, const char *runtime_config,
    cm_machine **new_machine) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const cartesi::machine_config c = cartesi::from_json<cartesi::machine_config>(config);
    const cartesi::machine_runtime_config r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config);
    const auto *cpp_mgr = convert_from_c(mgr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(create_jsonrpc_virtual_machine(*cpp_mgr, c, r));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_load_machine(const cm_jsonrpc_mgr *mgr, const char *dir, const char *runtime_config,
    cm_machine **new_machine) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const cartesi::machine_runtime_config r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config);
    const auto *cpp_mgr = convert_from_c(mgr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(load_jsonrpc_virtual_machine(*cpp_mgr, dir, r));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_get_machine(const cm_jsonrpc_mgr *mgr, cm_machine **new_machine) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const auto *cpp_mgr = convert_from_c(mgr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(get_jsonrpc_virtual_machine(*cpp_mgr));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_get_default_config(const cm_jsonrpc_mgr *mgr, const char **config) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::machine_config cpp_config = cartesi::jsonrpc_virtual_machine::get_default_config(*cpp_mgr);
    static THREAD_LOCAL char config_buf[CM_MAX_CONFIG_LENGTH];
    *config = string_to_buf(config_buf, sizeof(config_buf), cartesi::to_json(cpp_config).dump());
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_verify_step_uarch_log(const cm_jsonrpc_mgr *mgr, const cm_access_log *log, bool one_based) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::jsonrpc_virtual_machine::verify_step_uarch_log(*cpp_mgr, cpp_log, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_verify_step_uarch_state_transition(const cm_jsonrpc_mgr *mgr, const cm_hash *root_hash_before,
    const cm_access_log *log, const cm_hash *root_hash_after, bool one_based) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::access_log cpp_log = convert_from_c(log);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::jsonrpc_virtual_machine::verify_step_uarch_state_transition(*cpp_mgr, cpp_root_hash_before, cpp_log,
        cpp_root_hash_after, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_verify_reset_uarch_log(const cm_jsonrpc_mgr *mgr, const cm_access_log *log, bool one_based) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::jsonrpc_virtual_machine::verify_reset_uarch_log(*cpp_mgr, cpp_log, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_verify_reset_uarch_state_transition(const cm_jsonrpc_mgr *mgr, const cm_hash *root_hash_before,
    const cm_access_log *log, const cm_hash *root_hash_after, bool one_based) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::access_log cpp_log = convert_from_c(log);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::jsonrpc_virtual_machine::verify_reset_uarch_state_transition(*cpp_mgr, cpp_root_hash_before, cpp_log,
        cpp_root_hash_after, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_fork(const cm_jsonrpc_mgr *mgr, char **address, int *pid) try {
    if (address == nullptr) {
        throw std::invalid_argument("invalid address output");
    }
    const auto *cpp_mgr = convert_from_c(mgr);
    const auto result = cartesi::jsonrpc_virtual_machine::fork(*cpp_mgr);
    static THREAD_LOCAL char address_buf[64];
    *address = string_to_buf(address_buf, sizeof(address_buf), result.address);
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

int cm_jsonrpc_rebind(const cm_jsonrpc_mgr *mgr, const char *address, char **new_address) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const std::string cpp_new_address = cartesi::jsonrpc_virtual_machine::rebind(*cpp_mgr, address);
    if (new_address) {
        static THREAD_LOCAL char new_address_buf[64];
        *new_address = string_to_buf(new_address_buf, sizeof(new_address_buf), cpp_new_address);
    }
    return cm_result_success();
} catch (...) {
    if (new_address) {
        *new_address = nullptr;
    }
    return cm_result_failure();
}

int cm_jsonrpc_get_x_address(const cm_jsonrpc_mgr *mgr, int i, uint64_t *val) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    *val = cartesi::jsonrpc_virtual_machine::get_x_address(*cpp_mgr, i);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_get_f_address(const cm_jsonrpc_mgr *mgr, int i, uint64_t *val) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    *val = cartesi::jsonrpc_virtual_machine::get_f_address(*cpp_mgr, i);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_get_uarch_x_address(const cm_jsonrpc_mgr *mgr, int i, uint64_t *val) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    *val = cartesi::jsonrpc_virtual_machine::get_uarch_x_address(*cpp_mgr, i);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_get_csr_address(const cm_jsonrpc_mgr *mgr, CM_CSR csr, uint64_t *val) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const auto cpp_csr = static_cast<cartesi::machine::csr>(csr);
    *val = cartesi::jsonrpc_virtual_machine::get_csr_address(*cpp_mgr, cpp_csr);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_get_semantic_version(const cm_jsonrpc_mgr *mgr, const cm_semantic_version **version) try {
    if (version == nullptr) {
        throw std::invalid_argument("invalid version output");
    }
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::semantic_version cpp_version = cartesi::jsonrpc_virtual_machine::get_version(*cpp_mgr);
    *version = convert_to_c(cpp_version);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_shutdown(const cm_jsonrpc_mgr *mgr) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    cartesi::jsonrpc_virtual_machine::shutdown(*cpp_mgr);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_verify_send_cmio_response_log(const cm_jsonrpc_mgr *mgr, uint16_t reason, const unsigned char *data,
    size_t length, const cm_access_log *log, bool one_based) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::jsonrpc_virtual_machine::verify_send_cmio_response_log(*cpp_mgr, reason, data, length, cpp_log, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_jsonrpc_verify_send_cmio_response_state_transition(const cm_jsonrpc_mgr *mgr, uint16_t reason,
    const unsigned char *data, size_t length, const cm_hash *root_hash_before, const cm_access_log *log,
    const cm_hash *root_hash_after, bool one_based) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::access_log cpp_log = convert_from_c(log);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::jsonrpc_virtual_machine::verify_send_cmio_response_state_transition(*cpp_mgr, reason, data, length,
        cpp_root_hash_before, cpp_log, cpp_root_hash_after, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}
