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

#include "machine-c-api.h"
#include "machine-c-api-internal.h"

#include <any>
#include <cstring>
#include <exception>
#include <functional>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

#include "i-virtual-machine.h"
#include "json-util.h"
#include "machine-config.h"
#include "machine.h"
#include "os-features.h"
#include "semantic-version.h"
#include "virtual-machine.h"

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static THREAD_LOCAL std::string last_err_msg;

const char *cm_get_last_error_message() {
    return last_err_msg.c_str();
}

int32_t cm_result_failure() try { throw; } catch (std::exception &e) {
    try {
        last_err_msg = e.what();
        throw;
    } catch (std::invalid_argument &ex) {
        return CM_ERROR_INVALID_ARGUMENT;
    } catch (std::domain_error &ex) {
        return CM_ERROR_DOMAIN_ERROR;
    } catch (std::length_error &ex) {
        return CM_ERROR_LENGTH_ERROR;
    } catch (std::out_of_range &ex) {
        return CM_ERROR_OUT_OF_RANGE;
    } catch (std::logic_error &ex) {
        return CM_ERROR_LOGIC_ERROR;
    } catch (std::bad_optional_access &ex) {
        return CM_ERROR_BAD_OPTIONAL_ACCESS;
    } catch (std::range_error &ex) {
        return CM_ERROR_RANGE_ERROR;
    } catch (std::overflow_error &ex) {
        return CM_ERROR_OVERFLOW_ERROR;
    } catch (std::underflow_error &ex) {
        return CM_ERROR_UNDERFLOW_ERROR;
    } catch (std::regex_error &ex) {
        return CM_ERROR_REGEX_ERROR;
    } catch (std::system_error &ex) {
        return CM_ERROR_SYSTEM_ERROR;
    } catch (std::runtime_error &ex) {
        return CM_ERROR_RUNTIME_ERROR;
    } catch (std::bad_typeid &ex) {
        return CM_ERROR_BAD_TYPEID;
    } catch (std::bad_any_cast &ex) {
        return CM_ERROR_BAD_ANY_CAST;
    } catch (std::bad_cast &ex) {
        return CM_ERROR_BAD_CAST;
    } catch (std::bad_weak_ptr &ex) {
        return CM_ERROR_BAD_WEAK_PTR;
    } catch (std::bad_function_call &ex) {
        return CM_ERROR_BAD_FUNCTION_CALL;
    } catch (std::bad_array_new_length &ex) {
        return CM_ERROR_BAD_ARRAY_NEW_LENGTH;
    } catch (std::bad_alloc &ex) {
        return CM_ERROR_BAD_ALLOC;
    } catch (std::bad_exception &ex) {
        return CM_ERROR_BAD_EXCEPTION;
    } catch (std::bad_variant_access &ex) {
        return CM_ERROR_BAD_VARIANT_ACCESS;
    } catch (std::exception &e) {
        return CM_ERROR_EXCEPTION;
    }
} catch (...) {
    try {
        last_err_msg = std::string("unknown error");
    } catch (...) {
        // Failed to allocate string, last resort is to set an empty error.
        last_err_msg.clear();
    }
    return CM_ERROR_UNKNOWN;
}

int32_t cm_result_success() {
    last_err_msg.clear();
    return 0;
}

// --------------------------------------------
// Conversion functions
// --------------------------------------------
static cartesi::i_virtual_machine *convert_from_c(cm_machine *m) {
    if (m == nullptr) {
        throw std::invalid_argument("invalid machine");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<cartesi::i_virtual_machine *>(m);
}

static const cartesi::i_virtual_machine *convert_from_c(const cm_machine *m) {
    if (m == nullptr) {
        throw std::invalid_argument("invalid machine");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const cartesi::i_virtual_machine *>(m);
}

cartesi::machine_merkle_tree::hash_type convert_from_c(const cm_hash *c_hash) {
    if (c_hash == nullptr) {
        throw std::invalid_argument("invalid hash");
    }
    cartesi::machine_merkle_tree::hash_type cpp_hash; // In emulator this is std::array<unsigned char, hash_size>;
    memcpy(cpp_hash.data(), c_hash, sizeof(cm_hash));
    return cpp_hash;
}

// ----------------------------------------------
// The C API implementation
// ----------------------------------------------

int32_t cm_create(const char *config, const char *runtime_config, cm_machine **new_machine) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid machine configuration");
    }
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const auto c = cartesi::from_json<cartesi::machine_config>(config);
    cartesi::machine_runtime_config r;
    if (runtime_config) {
        r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config);
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(new cartesi::virtual_machine(c, r));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_load(const char *dir, const char *runtime_config, cm_machine **new_machine) try {
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
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(new cartesi::virtual_machine(dir, r));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

void cm_delete(cm_machine *m) {
    if (m == nullptr) {
        return;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    delete reinterpret_cast<cartesi::i_virtual_machine *>(m);
}

int32_t cm_store(cm_machine *m, const char *dir) try {
    if (dir == nullptr) {
        throw std::invalid_argument("invalid dir");
    }
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->store(dir);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_run(cm_machine *m, uint64_t mcycle_end, CM_BREAK_REASON *break_reason) try {
    auto *cpp_machine = convert_from_c(m);
    const auto status = cpp_machine->run(mcycle_end);
    if (break_reason) {
        *break_reason = static_cast<CM_BREAK_REASON>(status);
    }
    return cm_result_success();
} catch (...) {
    if (break_reason) {
        *break_reason = CM_BREAK_REASON_FAILED;
    }
    return cm_result_failure();
}

int32_t cm_read_uarch_halt_flag(const cm_machine *m, bool *val) try {
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_uarch_halt_flag();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_set_uarch_halt_flag(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->set_uarch_halt_flag();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_reset_uarch(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->reset_uarch();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_log_reset_uarch(cm_machine *m, int32_t log_type, bool one_based, const char **access_log) try {
    if (access_log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::access_log::type cpp_log_type(log_type);
    cartesi::access_log cpp_access_log = cpp_machine->log_reset_uarch(cpp_log_type, one_based);
    static THREAD_LOCAL std::string access_log_storage;
    access_log_storage = cartesi::to_json(cpp_access_log).dump();
    *access_log = access_log_storage.c_str();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_run_uarch(cm_machine *m, uint64_t uarch_cycle_end, CM_UARCH_BREAK_REASON *uarch_break_reason) try {
    auto *cpp_machine = convert_from_c(m);
    const auto status = cpp_machine->run_uarch(uarch_cycle_end);
    if (uarch_break_reason) {
        *uarch_break_reason = static_cast<CM_UARCH_BREAK_REASON>(status);
    }
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_log_step_uarch(cm_machine *m, int32_t log_type, bool one_based, const char **access_log) try {
    if (access_log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::access_log::type cpp_log_type(log_type);
    cartesi::access_log cpp_access_log = cpp_machine->log_step_uarch(cpp_log_type, one_based);
    static THREAD_LOCAL std::string access_log_storage;
    access_log_storage = cartesi::to_json(cpp_access_log).dump();
    *access_log = access_log_storage.c_str();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_verify_step_uarch(const cm_hash *root_hash_before, const char *access_log, const cm_hash *root_hash_after,
    bool one_based) try {
    if (access_log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto cpp_access_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(access_log).value();
    if (root_hash_before || root_hash_after) {
        const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
        const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
        cartesi::machine::verify_step_uarch_state_transition(cpp_root_hash_before, cpp_access_log, cpp_root_hash_after,
            one_based);
    } else {
        cartesi::machine::verify_step_uarch_log(cpp_access_log, one_based);
    }
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_verify_reset_uarch(const cm_hash *root_hash_before, const char *access_log, const cm_hash *root_hash_after,
    bool one_based) try {
    if (access_log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto cpp_access_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(access_log).value();
    if (root_hash_before || root_hash_after) {
        const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
        const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
        cartesi::machine::verify_reset_uarch_state_transition(cpp_root_hash_before, cpp_access_log, cpp_root_hash_after,
            one_based);
    } else {
        cartesi::machine::verify_reset_uarch_log(cpp_access_log, one_based);
    }
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_get_proof(cm_machine *m, uint64_t address, int32_t log2_size, const char **proof) try {
    if (proof == nullptr) {
        throw std::invalid_argument("invalid proof output");
    }
    auto *cpp_machine = convert_from_c(m);
    const cartesi::machine_merkle_tree::proof_type cpp_proof = cpp_machine->get_proof(address, log2_size);
    static THREAD_LOCAL std::string proof_storage;
    proof_storage = cartesi::to_json(cpp_proof).dump();
    *proof = proof_storage.c_str();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_get_root_hash(cm_machine *m, cm_hash *hash) try {
    if (hash == nullptr) {
        throw std::invalid_argument("invalid hash output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::machine_merkle_tree::hash_type cpp_hash;
    cpp_machine->get_root_hash(cpp_hash);
    memcpy(hash, static_cast<const uint8_t *>(cpp_hash.data()), sizeof(cm_hash));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_verify_merkle_tree(cm_machine *m, bool *result) try {
    if (result == nullptr) {
        throw std::invalid_argument("invalid result output");
    }
    auto *cpp_machine = convert_from_c(m);
    *result = cpp_machine->verify_merkle_tree();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_read_csr(const cm_machine *m, CM_CSR csr, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    auto cpp_csr = static_cast<cartesi::machine::csr>(csr);
    *val = cpp_machine->read_csr(cpp_csr);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_write_csr(cm_machine *m, CM_CSR csr, uint64_t val) try {
    auto *cpp_machine = convert_from_c(m);
    auto cpp_csr = static_cast<cartesi::machine::csr>(csr);
    cpp_machine->write_csr(cpp_csr, val);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

uint64_t cm_get_csr_address(CM_CSR csr) try {
    auto cpp_csr = static_cast<cartesi::machine::csr>(csr);
    uint64_t address = cartesi::machine::get_csr_address(cpp_csr);
    cm_result_success();
    return address;
} catch (...) {
    cm_result_failure();
    return UINT64_MAX;
}

int32_t cm_read_word(const cm_machine *m, uint64_t address, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid word output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_word(address);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_read_memory(const cm_machine *m, uint64_t address, uint8_t *data, uint64_t length) try {
    const auto *cpp_machine = convert_from_c(m);
    cpp_machine->read_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_write_memory(cm_machine *m, uint64_t address, const uint8_t *data, uint64_t length) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->write_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_read_virtual_memory(const cm_machine *m, uint64_t address, uint8_t *data, uint64_t length) try {
    const auto *cpp_machine = convert_from_c(m);
    cpp_machine->read_virtual_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_write_virtual_memory(cm_machine *m, uint64_t address, const uint8_t *data, uint64_t length) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->write_virtual_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_translate_virtual_address(const cm_machine *m, uint64_t vaddr, uint64_t *paddr) try {
    const auto *cpp_machine = convert_from_c(m);
    *paddr = cpp_machine->translate_virtual_address(vaddr);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_read_mcycle(const cm_machine *m, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_mcycle();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_read_uarch_cycle(const cm_machine *m, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_uarch_cycle();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_read_iflags_Y(const cm_machine *m, bool *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_iflags_Y();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_reset_iflags_Y(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->reset_iflags_Y();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_set_iflags_Y(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->set_iflags_Y();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_read_iflags_X(const cm_machine *m, bool *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_iflags_X();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_read_iflags_H(const cm_machine *m, bool *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_iflags_H();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_verify_dirty_page_maps(cm_machine *m, bool *result) try {
    if (result == nullptr) {
        throw std::invalid_argument("invalid result output");
    }
    auto *cpp_machine = convert_from_c(m);
    *result = cpp_machine->verify_dirty_page_maps();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_get_initial_config(const cm_machine *m, const char **config) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    const auto *cpp_machine = convert_from_c(m);
    const cartesi::machine_config cpp_config = cpp_machine->get_initial_config();
    static THREAD_LOCAL std::string config_storage;
    config_storage = cartesi::to_json(cpp_config).dump();
    *config = config_storage.c_str();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

const char *cm_get_default_config() try {
    const cartesi::machine_config cpp_config = cartesi::machine::get_default_config();
    static THREAD_LOCAL std::string config_storage;
    config_storage = cartesi::to_json(cpp_config).dump();
    const char *config = config_storage.c_str();
    cm_result_success();
    return config;
} catch (...) {
    cm_result_failure();
    return nullptr;
}

int32_t cm_replace_memory_range(cm_machine *m, uint64_t start, uint64_t length, bool shared,
    const char *image_filename) try {
    auto *cpp_machine = convert_from_c(m);
    cartesi::memory_range_config cpp_range;
    cpp_range.start = start;
    cpp_range.length = length;
    cpp_range.shared = shared;
    cpp_range.image_filename = image_filename ? image_filename : "";
    cpp_machine->replace_memory_range(cpp_range);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_destroy(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->destroy();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_snapshot(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->snapshot();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_commit(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->commit();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_rollback(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->rollback();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_get_memory_ranges(const cm_machine *m, const char **ranges) try {
    if (ranges == nullptr) {
        throw std::invalid_argument("invalid memory range output");
    }
    const auto *cpp_machine = convert_from_c(m);
    const cartesi::machine_memory_range_descrs cpp_ranges = cpp_machine->get_memory_ranges();
    static THREAD_LOCAL std::string ranges_storage;
    ranges_storage = cartesi::to_json(cpp_ranges).dump();
    *ranges = ranges_storage.c_str();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->send_cmio_response(reason, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_log_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length,
    int32_t log_type, bool one_based, const char **access_log) try {
    if (access_log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::access_log::type cpp_log_type(log_type);
    cartesi::access_log cpp_access_log =
        cpp_machine->log_send_cmio_response(reason, data, length, cpp_log_type, one_based);
    static THREAD_LOCAL std::string access_log_storage;
    access_log_storage = cartesi::to_json(cpp_access_log).dump();
    *access_log = access_log_storage.c_str();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int32_t cm_verify_send_cmio_response(uint16_t reason, const uint8_t *data, uint64_t length,
    const cm_hash *root_hash_before, const char *access_log, const cm_hash *root_hash_after, bool one_based) try {
    if (access_log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto cpp_access_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(access_log).value();
    if (root_hash_before || root_hash_after) {
        const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
        const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
        cartesi::machine::verify_send_cmio_response_state_transition(reason, data, length, cpp_root_hash_before,
            cpp_access_log, cpp_root_hash_after, one_based);
    } else {
        cartesi::machine::verify_send_cmio_response_log(reason, data, length, cpp_access_log, one_based);
    }
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}
