// Copyright 2023 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include "grpc-machine-c-api.h"
#include "grpc-virtual-machine.h"
#include "i-virtual-machine.h"
#include "machine-c-api-internal.h"
#include "virtual-machine.h"

static const cartesi::grpc_machine_stub_ptr *convert_from_c(const cm_grpc_machine_stub *stub) {
    if (stub == nullptr) {
        throw std::invalid_argument("invalid stub");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
}

static cartesi::grpc_machine_stub_ptr *convert_from_c(cm_grpc_machine_stub *stub) {
    if (stub == nullptr) {
        throw std::invalid_argument("invalid stub");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cartesi::grpc_machine_stub_ptr *>(stub);
}

static inline cartesi::i_virtual_machine *create_grpc_virtual_machine(const cartesi::grpc_machine_stub_ptr &stub,
    const cartesi::machine_config &c, const cartesi::machine_runtime_config &r) {
    return new cartesi::grpc_virtual_machine(stub, c, r);
}

static inline cartesi::i_virtual_machine *load_grpc_virtual_machine(const cartesi::grpc_machine_stub_ptr &stub,
    const char *dir, const cartesi::machine_runtime_config &r) {
    return new cartesi::grpc_virtual_machine(stub, null_to_empty(dir), r);
}

static inline cartesi::i_virtual_machine *get_grpc_virtual_machine(const cartesi::grpc_machine_stub_ptr &stub) {
    return new cartesi::grpc_virtual_machine(stub);
}

int cm_create_grpc_machine_stub(const char *remote_address, const char *checkin_address, cm_grpc_machine_stub **stub,
    char **err_msg) try {
    if (stub == nullptr) {
        throw std::invalid_argument("invalid stub output");
    }
    auto *cpp_stub = new std::shared_ptr<cartesi::grpc_machine_stub>(
        new cartesi::grpc_machine_stub{null_to_empty(remote_address), null_to_empty(checkin_address)});
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *stub = reinterpret_cast<cm_grpc_machine_stub *>(cpp_stub);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

void cm_delete_grpc_machine_stub(const cm_grpc_machine_stub *stub) {
    if (stub == nullptr) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *stub_wrapper = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    delete stub_wrapper;
}

int cm_create_grpc_machine(const cm_grpc_machine_stub *stub, const cm_machine_config *config,
    const cm_machine_runtime_config *runtime_config, cm_machine **new_machine, char **err_msg) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const cartesi::machine_config c = convert_from_c(config);
    const cartesi::machine_runtime_config r = convert_from_c(runtime_config);
    const auto *cpp_stub = convert_from_c(stub);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(create_grpc_virtual_machine(*cpp_stub, c, r));
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_load_grpc_machine(const cm_grpc_machine_stub *stub, const char *dir,
    const cm_machine_runtime_config *runtime_config, cm_machine **new_machine, char **err_msg) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const cartesi::machine_runtime_config r = convert_from_c(runtime_config);
    const auto *cpp_stub = convert_from_c(stub);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(load_grpc_virtual_machine(*cpp_stub, dir, r));
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_get_grpc_machine(const cm_grpc_machine_stub *stub, cm_machine **new_machine, char **err_msg) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const auto *cpp_stub = convert_from_c(stub);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(get_grpc_virtual_machine(*cpp_stub));
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_get_default_config(const cm_grpc_machine_stub *stub, const cm_machine_config **config, char **err_msg) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    const auto *cpp_stub = convert_from_c(stub);
    const cartesi::machine_config cpp_config = cartesi::grpc_virtual_machine::get_default_config(*cpp_stub);
    *config = convert_to_c(cpp_config);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_verify_access_log(const cm_grpc_machine_stub *stub, const cm_access_log *log,
    const cm_machine_runtime_config *runtime_config, bool one_based, char **err_msg) try {
    const auto *cpp_stub = convert_from_c(stub);
    const cartesi::access_log cpp_log = convert_from_c(log);
    const cartesi::machine_runtime_config cpp_runtime = convert_from_c(runtime_config);
    cartesi::grpc_virtual_machine::verify_access_log(*cpp_stub, cpp_log, cpp_runtime, one_based);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_verify_state_transition(const cm_grpc_machine_stub *stub, const cm_hash *root_hash_before,
    const cm_access_log *log, const cm_hash *root_hash_after, const cm_machine_runtime_config *runtime_config,
    bool one_based, char **err_msg) try {
    const auto *cpp_stub = convert_from_c(stub);
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    const cartesi::access_log cpp_log = convert_from_c(log);
    const cartesi::machine_runtime_config cpp_runtime = convert_from_c(runtime_config);
    cartesi::grpc_virtual_machine::verify_state_transition(*cpp_stub, cpp_root_hash_before, cpp_log,
        cpp_root_hash_after, cpp_runtime, one_based);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_get_x_address(const cm_grpc_machine_stub *stub, int i, uint64_t *val, char **err_msg) try {
    const auto *cpp_stub = convert_from_c(stub);
    *val = cartesi::grpc_virtual_machine::get_x_address(*cpp_stub, i);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_get_uarch_x_address(const cm_grpc_machine_stub *stub, int i, uint64_t *val, char **err_msg) try {
    const auto *cpp_stub = convert_from_c(stub);
    *val = cartesi::grpc_virtual_machine::get_uarch_x_address(*cpp_stub, i);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_get_csr_address(const cm_grpc_machine_stub *stub, CM_PROC_CSR w, uint64_t *val, char **err_msg) try {
    const auto *cpp_stub = convert_from_c(stub);
    const auto cpp_csr = static_cast<cartesi::machine::csr>(w);
    *val = cartesi::grpc_virtual_machine::get_csr_address(*cpp_stub, cpp_csr);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_get_semantic_version(const cm_grpc_machine_stub *stub, const cm_semantic_version **version,
    char **err_msg) try {
    if (version == nullptr) {
        throw std::invalid_argument("invalid version output");
    }
    const auto *cpp_stub = convert_from_c(stub);
    const cartesi::semantic_version cpp_version = cartesi::grpc_virtual_machine::get_version(*cpp_stub);
    *version = convert_to_c(cpp_version);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_shutdown(const cm_grpc_machine_stub *stub, char **err_msg) try {
    const auto *cpp_stub = convert_from_c(stub);
    cartesi::grpc_virtual_machine::shutdown(*cpp_stub);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}
