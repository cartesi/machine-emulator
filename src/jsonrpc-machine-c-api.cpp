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
#include "jsonrpc-mg-mgr.h"
#include "jsonrpc-virtual-machine.h"
#include "machine-c-api-internal.h"
#include "virtual-machine.h"

static const cartesi::jsonrpc_mg_mgr_ptr *convert_from_c(const cm_jsonrpc_mg_mgr *mgr) {
    if (mgr == nullptr) {
        throw std::invalid_argument("invalid stub");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const cartesi::jsonrpc_mg_mgr_ptr *>(mgr);
}

static cartesi::jsonrpc_mg_mgr_ptr *convert_from_c(cm_jsonrpc_mg_mgr *mgr) {
    if (mgr == nullptr) {
        throw std::invalid_argument("invalid stub");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cartesi::jsonrpc_mg_mgr_ptr *>(mgr);
}

static inline cartesi::i_virtual_machine *create_jsonrpc_virtual_machine(const cartesi::jsonrpc_mg_mgr_ptr &mgr,
    const cartesi::machine_config &c, const cartesi::machine_runtime_config &r) {
    return new cartesi::jsonrpc_virtual_machine(mgr, c, r);
}

static inline cartesi::i_virtual_machine *load_jsonrpc_virtual_machine(const cartesi::jsonrpc_mg_mgr_ptr &mgr,
    const char *dir, const cartesi::machine_runtime_config &r) {
    return new cartesi::jsonrpc_virtual_machine(mgr, null_to_empty(dir), r);
}

static inline cartesi::i_virtual_machine *get_jsonrpc_virtual_machine(const cartesi::jsonrpc_mg_mgr_ptr &mgr) {
    return new cartesi::jsonrpc_virtual_machine(mgr);
}

int cm_create_jsonrpc_mg_mgr(const char *remote_address, cm_jsonrpc_mg_mgr **mgr, char **err_msg) try {
    if (mgr == nullptr) {
        throw std::invalid_argument("invalid stub output");
    }
    auto *cpp_mgr =
        new std::shared_ptr<cartesi::jsonrpc_mg_mgr>(new cartesi::jsonrpc_mg_mgr{null_to_empty(remote_address)});
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *mgr = reinterpret_cast<cm_jsonrpc_mg_mgr *>(cpp_mgr);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

void cm_delete_jsonrpc_mg_mgr(const cm_jsonrpc_mg_mgr *mgr) {
    if (mgr == nullptr) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *mgr_wrapper = reinterpret_cast<const cartesi::jsonrpc_mg_mgr_ptr *>(mgr);
    delete mgr_wrapper;
}

int cm_create_jsonrpc_machine(const cm_jsonrpc_mg_mgr *mgr, const cm_machine_config *config,
    const cm_machine_runtime_config *runtime_config, cm_machine **new_machine, char **err_msg) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const cartesi::machine_config c = convert_from_c(config);
    const cartesi::machine_runtime_config r = convert_from_c(runtime_config);
    const auto *cpp_mgr = convert_from_c(mgr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(create_jsonrpc_virtual_machine(*cpp_mgr, c, r));
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_load_jsonrpc_machine(const cm_jsonrpc_mg_mgr *mgr, const char *dir,
    const cm_machine_runtime_config *runtime_config, cm_machine **new_machine, char **err_msg) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const cartesi::machine_runtime_config r = convert_from_c(runtime_config);
    const auto *cpp_mgr = convert_from_c(mgr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(load_jsonrpc_virtual_machine(*cpp_mgr, dir, r));
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_get_jsonrpc_machine(const cm_jsonrpc_mg_mgr *mgr, cm_machine **new_machine, char **err_msg) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const auto *cpp_mgr = convert_from_c(mgr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(get_jsonrpc_virtual_machine(*cpp_mgr));
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_get_default_config(const cm_jsonrpc_mg_mgr *mgr, const cm_machine_config **config, char **err_msg) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::machine_config cpp_config = cartesi::jsonrpc_virtual_machine::get_default_config(*cpp_mgr);
    *config = convert_to_c(cpp_config);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_verify_access_log(const cm_jsonrpc_mg_mgr *mgr, const cm_access_log *log,
    const cm_machine_runtime_config *runtime_config, bool one_based, char **err_msg) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::access_log cpp_log = convert_from_c(log);
    const cartesi::machine_runtime_config cpp_runtime = convert_from_c(runtime_config);
    cartesi::jsonrpc_virtual_machine::verify_access_log(*cpp_mgr, cpp_log, cpp_runtime, one_based);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_verify_state_transition(const cm_jsonrpc_mg_mgr *mgr, const cm_hash *root_hash_before,
    const cm_access_log *log, const cm_hash *root_hash_after, const cm_machine_runtime_config *runtime_config,
    bool one_based, char **err_msg) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::access_log cpp_log = convert_from_c(log);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    const cartesi::machine_runtime_config cpp_runtime = convert_from_c(runtime_config);
    cartesi::jsonrpc_virtual_machine::verify_state_transition(*cpp_mgr, cpp_root_hash_before, cpp_log,
        cpp_root_hash_after, cpp_runtime, one_based);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_fork(const cm_jsonrpc_mg_mgr *mgr, char **address, char **err_msg) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    auto cpp_address = cartesi::jsonrpc_virtual_machine::fork(*cpp_mgr);
    *address = convert_to_c(cpp_address);
    return cm_result_success(err_msg);
} catch (...) {
    *address = nullptr;
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_get_x_address(const cm_jsonrpc_mg_mgr *mgr, int i, uint64_t *val, char **err_msg) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    *val = cartesi::jsonrpc_virtual_machine::get_x_address(*cpp_mgr, i);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_get_f_address(const cm_jsonrpc_mg_mgr *mgr, int i, uint64_t *val, char **err_msg) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    *val = cartesi::jsonrpc_virtual_machine::get_f_address(*cpp_mgr, i);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_get_uarch_x_address(const cm_jsonrpc_mg_mgr *mgr, int i, uint64_t *val, char **err_msg) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    *val = cartesi::jsonrpc_virtual_machine::get_uarch_x_address(*cpp_mgr, i);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_get_csr_address(const cm_jsonrpc_mg_mgr *mgr, CM_PROC_CSR w, uint64_t *val, char **err_msg) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    const auto cpp_csr = static_cast<cartesi::machine::csr>(w);
    *val = cartesi::jsonrpc_virtual_machine::get_csr_address(*cpp_mgr, cpp_csr);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_get_semantic_version(const cm_jsonrpc_mg_mgr *mgr, const cm_semantic_version **version,
    char **err_msg) try {
    if (version == nullptr) {
        throw std::invalid_argument("invalid version output");
    }
    const auto *cpp_mgr = convert_from_c(mgr);
    const cartesi::semantic_version cpp_version = cartesi::jsonrpc_virtual_machine::get_version(*cpp_mgr);
    *version = convert_to_c(cpp_version);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_jsonrpc_shutdown(const cm_jsonrpc_mg_mgr *mgr, char **err_msg) try {
    const auto *cpp_mgr = convert_from_c(mgr);
    cartesi::jsonrpc_virtual_machine::shutdown(*cpp_mgr);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}
