
#include "semantic-version.h"
#include "i-virtual-machine.h"
#include "virtual-machine.h"
#include "grpc-virtual-machine.h"
#include "grpc-machine-c-api.h"
#include "machine-c-api-internal.h"

static cm_semantic_version *convert_to_c(const cartesi::semantic_version &cpp_version) {
    cm_semantic_version *new_semantic_version = new cm_semantic_version{};
    new_semantic_version->major = cpp_version.major;
    new_semantic_version->minor = cpp_version.minor;
    new_semantic_version->patch = cpp_version.patch;
    new_semantic_version->pre_release = convert_to_c(cpp_version.pre_release);
    new_semantic_version->build = convert_to_c(cpp_version.build);
    return new_semantic_version;
}


static inline cartesi::i_virtual_machine *create_grpc_virtual_machine(const cartesi::grpc_machine_stub_ptr &stub,
                                                                      const cartesi::machine_config &c,
                                                                      const cartesi::machine_runtime_config &r) {
    return new cartesi::grpc_virtual_machine(stub, c, r);
}

static inline cartesi::i_virtual_machine *load_grpc_virtual_machine(const cartesi::grpc_machine_stub_ptr &stub,
                                                                    const char *dir,
                                                                    const cartesi::machine_runtime_config &r) {
    return new cartesi::grpc_virtual_machine(stub, null_to_empty(dir), r);
}


int cm_create_grpc_machine_stub(const char *address, cm_grpc_machine_stub **stub, char **err_msg) try {
    cartesi::grpc_machine_stub_ptr *cpp_stub = new std::shared_ptr<cartesi::grpc_machine_stub>(
        new cartesi::grpc_machine_stub{null_to_empty(address)});
    *stub = reinterpret_cast<cm_grpc_machine_stub *>(cpp_stub);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

void cm_delete_grpc_machine_stub(const cm_grpc_machine_stub *stub) {
    if (stub == nullptr) {
        return;
    }
    const cartesi::grpc_machine_stub_ptr *stub_wrapper =
        reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    delete stub_wrapper;
}

int cm_create_grpc_machine(const cm_grpc_machine_stub *stub, const cm_machine_config *config,
                           const cm_machine_runtime_config *runtime_config,
                           cm_machine **new_machine, char **err_msg) try {
    const cartesi::machine_config c = convert_from_c(config);
    const cartesi::machine_runtime_config r = convert_from_c(runtime_config);
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    *new_machine = reinterpret_cast<cm_machine *>(create_grpc_virtual_machine(*cpp_stub, c, r));
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}


int cm_load_grpc_machine(const cm_grpc_machine_stub *stub, const char *dir, const cm_machine_runtime_config *runtime_config,
                     cm_machine **new_machine, char **err_msg) try {
    const cartesi::machine_runtime_config r = convert_from_c(runtime_config);
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    *new_machine = reinterpret_cast<cm_machine *>(load_grpc_virtual_machine(*cpp_stub, dir, r));
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_get_default_config(const cm_grpc_machine_stub *stub, const cm_machine_config **config, char **err_msg) try {
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    const cartesi::machine_config cpp_config = cartesi::grpc_virtual_machine::get_default_config(
        *cpp_stub);
    *config = convert_to_c(cpp_config);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_verify_access_log(const cm_grpc_machine_stub *stub, const cm_access_log *log, bool one_based,
                              char **err_msg) try {
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::grpc_virtual_machine::verify_access_log(*cpp_stub, cpp_log, one_based);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_verify_state_transition(const cm_grpc_machine_stub *stub,
                                    const cm_hash *root_hash_before,
                                    const cm_access_log *log, const cm_hash *root_hash_after,
                                    bool one_based,
                                    char **err_msg) try {
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::grpc_virtual_machine::verify_state_transition(*cpp_stub, cpp_root_hash_before, cpp_log,
        cpp_root_hash_after,
        one_based);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_get_x_address(const cm_grpc_machine_stub *stub, int i, uint64_t *val, char **err_msg) try {
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    *val = cartesi::grpc_virtual_machine::get_x_address(*cpp_stub, i);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_get_csr_address(const cm_grpc_machine_stub *stub, CM_PROC_CSR w, uint64_t *val, char **err_msg) try {
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    const cartesi::machine::csr cpp_csr = static_cast<cartesi::machine::csr>(w);
    *val = cartesi::grpc_virtual_machine::get_csr_address(*cpp_stub, cpp_csr);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_dhd_h_address(const cm_grpc_machine_stub *stub, int i, uint64_t *val, char **err_msg) try {
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    *val = cartesi::grpc_virtual_machine::get_dhd_h_address(*cpp_stub, i);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

int cm_grpc_get_semantic_version(const cm_grpc_machine_stub *stub, const cm_semantic_version **version, char **err_msg) try {
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    const cartesi::semantic_version cpp_version = cartesi::grpc_virtual_machine::get_version(*cpp_stub);
    *version = convert_to_c(cpp_version);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}

void cm_delete_semantic_version(const cm_semantic_version *version) {
    if (version == nullptr) {
        return;
    }

    delete[] version->pre_release;
    delete[] version->build;
    delete version;
}

int cm_grpc_shutdown(const cm_grpc_machine_stub *stub, char **err_msg) try {
    const cartesi::grpc_machine_stub_ptr *cpp_stub = reinterpret_cast<const cartesi::grpc_machine_stub_ptr *>(stub);
    cartesi::grpc_virtual_machine::shutdown(*cpp_stub);
    return cm_result_success(err_msg);
} catch (...) {
    return cm_result_failure(err_msg);
}
