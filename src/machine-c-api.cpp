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

#include "htif.h"
#include "pma-constants.h"

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static THREAD_LOCAL std::string last_err_msg;

const char *cm_get_last_error_message() {
    return last_err_msg.c_str();
}

const char *cm_set_temp_string(const std::string &s) {
    static THREAD_LOCAL std::string temp_string;
    temp_string = s;
    return temp_string.c_str();
}

cm_error cm_result_failure() try { throw; } catch (std::exception &e) {
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

cm_error cm_result_success() {
    last_err_msg.clear();
    return CM_ERROR_OK;
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

cm_error cm_create(const char *config, const char *runtime_config, cm_machine **new_machine) try {
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
    if (new_machine) {
        *new_machine = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_load(const char *dir, const char *runtime_config, cm_machine **new_machine) try {
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
    if (new_machine) {
        *new_machine = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_store(const cm_machine *m, const char *dir) try {
    if (dir == nullptr) {
        throw std::invalid_argument("invalid dir");
    }
    const auto *cpp_machine = convert_from_c(m);
    cpp_machine->store(dir);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_run(cm_machine *m, uint64_t mcycle_end, cm_break_reason *break_reason) try {
    auto *cpp_machine = convert_from_c(m);
    const auto status = cpp_machine->run(mcycle_end);
    if (break_reason) {
        *break_reason = static_cast<cm_break_reason>(status);
    }
    return cm_result_success();
} catch (...) {
    if (break_reason) {
        *break_reason = CM_BREAK_REASON_FAILED;
    }
    return cm_result_failure();
}

cm_error cm_read_uarch_halt_flag(const cm_machine *m, bool *val) try {
    const auto *cpp_machine = convert_from_c(m);
    *val = static_cast<bool>(cpp_machine->read_reg(cartesi::machine::reg::uarch_halt_flag));
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = false;
    }
    return cm_result_failure();
}

cm_error cm_set_uarch_halt_flag(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->write_reg(cartesi::machine::reg::uarch_halt_flag, 1);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_reset_uarch(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->reset_uarch();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_log_reset_uarch(cm_machine *m, int32_t log_type, const char **log) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::access_log::type cpp_log_type(log_type);
    cartesi::access_log cpp_log = cpp_machine->log_reset_uarch(cpp_log_type);
    *log = cm_set_temp_string(cartesi::to_json(cpp_log).dump());
    return cm_result_success();
} catch (...) {
    if (log) {
        *log = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_run_uarch(cm_machine *m, uint64_t uarch_cycle_end, cm_uarch_break_reason *uarch_break_reason) try {
    auto *cpp_machine = convert_from_c(m);
    const auto status = cpp_machine->run_uarch(uarch_cycle_end);
    if (uarch_break_reason) {
        *uarch_break_reason = static_cast<cm_uarch_break_reason>(status);
    }
    return cm_result_success();
} catch (...) {
    if (uarch_break_reason) {
        *uarch_break_reason = CM_UARCH_BREAK_REASON_FAILED;
    }
    return cm_result_failure();
}

cm_error cm_log_step_uarch(cm_machine *m, int32_t log_type, const char **log) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::access_log::type cpp_log_type(log_type);
    cartesi::access_log cpp_log = cpp_machine->log_step_uarch(cpp_log_type);
    *log = cm_set_temp_string(cartesi::to_json(cpp_log).dump());
    return cm_result_success();
} catch (...) {
    if (log) {
        *log = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_verify_step_uarch(const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log).value();
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::machine::verify_step_uarch(cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_verify_reset_uarch(const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log).value();
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::machine::verify_reset_uarch(cpp_root_hash_before, cpp_log, cpp_root_hash_after);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_get_proof(const cm_machine *m, uint64_t address, int32_t log2_size, const char **proof) try {
    if (proof == nullptr) {
        throw std::invalid_argument("invalid proof output");
    }
    const auto *cpp_machine = convert_from_c(m);
    const cartesi::machine_merkle_tree::proof_type cpp_proof = cpp_machine->get_proof(address, log2_size);
    *proof = cm_set_temp_string(cartesi::to_json(cpp_proof).dump());
    return cm_result_success();
} catch (...) {
    if (proof) {
        *proof = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_get_root_hash(const cm_machine *m, cm_hash *hash) try {
    if (hash == nullptr) {
        throw std::invalid_argument("invalid hash output");
    }
    const auto *cpp_machine = convert_from_c(m);
    cartesi::machine_merkle_tree::hash_type cpp_hash;
    cpp_machine->get_root_hash(cpp_hash);
    memcpy(hash, static_cast<const uint8_t *>(cpp_hash.data()), sizeof(cm_hash));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_verify_merkle_tree(cm_machine *m, bool *result) try {
    if (result == nullptr) {
        throw std::invalid_argument("invalid result output");
    }
    auto *cpp_machine = convert_from_c(m);
    *result = cpp_machine->verify_merkle_tree();
    return cm_result_success();
} catch (...) {
    if (result) {
        *result = false;
    }
    return cm_result_failure();
}

cm_error cm_read_reg(const cm_machine *m, cm_reg reg, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    auto cpp_reg = static_cast<cartesi::machine::reg>(reg);
    *val = cpp_machine->read_reg(cpp_reg);
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_write_reg(cm_machine *m, cm_reg reg, uint64_t val) try {
    auto *cpp_machine = convert_from_c(m);
    auto cpp_reg = static_cast<cartesi::machine::reg>(reg);
    cpp_machine->write_reg(cpp_reg, val);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_get_reg_address(cm_reg reg, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    auto cpp_reg = static_cast<cartesi::machine::reg>(reg);
    *val = cartesi::machine::get_reg_address(cpp_reg);
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_read_word(const cm_machine *m, uint64_t address, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid word output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_word(address);
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_read_memory(const cm_machine *m, uint64_t address, uint8_t *data, uint64_t length) try {
    const auto *cpp_machine = convert_from_c(m);
    cpp_machine->read_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_write_memory(cm_machine *m, uint64_t address, const uint8_t *data, uint64_t length) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->write_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_read_virtual_memory(const cm_machine *m, uint64_t address, uint8_t *data, uint64_t length) try {
    const auto *cpp_machine = convert_from_c(m);
    cpp_machine->read_virtual_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_write_virtual_memory(cm_machine *m, uint64_t address, const uint8_t *data, uint64_t length) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->write_virtual_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_translate_virtual_address(const cm_machine *m, uint64_t vaddr, uint64_t *paddr) try {
    const auto *cpp_machine = convert_from_c(m);
    *paddr = cpp_machine->translate_virtual_address(vaddr);
    return cm_result_success();
} catch (...) {
    if (paddr) {
        *paddr = 0;
    }
    return cm_result_failure();
}

cm_error cm_read_mcycle(const cm_machine *m, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_reg(cartesi::machine::reg::mcycle);
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_read_uarch_cycle(const cm_machine *m, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_reg(cartesi::machine::reg::uarch_cycle);
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = 0;
    }
    return cm_result_failure();
}

cm_error cm_read_iflags_Y(const cm_machine *m, bool *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = static_cast<bool>(cpp_machine->read_reg(cartesi::machine::reg::iflags_y));
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = false;
    }
    return cm_result_failure();
}

cm_error cm_reset_iflags_Y(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->write_reg(cartesi::machine::reg::iflags_y, 0);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_set_iflags_Y(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->write_reg(cartesi::machine::reg::iflags_y, 1);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_read_iflags_X(const cm_machine *m, bool *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = static_cast<bool>(cpp_machine->read_reg(cartesi::machine::reg::iflags_x));
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = false;
    }
    return cm_result_failure();
}

cm_error cm_read_iflags_H(const cm_machine *m, bool *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = static_cast<bool>(cpp_machine->read_reg(cartesi::machine::reg::iflags_h));
    return cm_result_success();
} catch (...) {
    if (val) {
        *val = false;
    }
    return cm_result_failure();
}

cm_error cm_verify_dirty_page_maps(cm_machine *m, bool *result) try {
    if (result == nullptr) {
        throw std::invalid_argument("invalid result output");
    }
    auto *cpp_machine = convert_from_c(m);
    *result = cpp_machine->verify_dirty_page_maps();
    return cm_result_success();
} catch (...) {
    if (result) {
        *result = false;
    }
    return cm_result_failure();
}

cm_error cm_get_initial_config(const cm_machine *m, const char **config) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    const auto *cpp_machine = convert_from_c(m);
    const cartesi::machine_config cpp_config = cpp_machine->get_initial_config();
    *config = cm_set_temp_string(cartesi::to_json(cpp_config).dump());
    return cm_result_success();
} catch (...) {
    if (config) {
        *config = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_get_default_config(const char **config) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    const cartesi::machine_config cpp_config = cartesi::machine::get_default_config();
    *config = cm_set_temp_string(cartesi::to_json(cpp_config).dump());
    return cm_result_success();
} catch (...) {
    if (config) {
        *config = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_replace_memory_range(cm_machine *m, uint64_t start, uint64_t length, bool shared,
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

cm_error cm_destroy(cm_machine *m) try {
    if (m != nullptr) {
        auto *cpp_machine = convert_from_c(m);
        delete cpp_machine;
    }
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_snapshot(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->snapshot();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_commit(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->commit();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_rollback(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->rollback();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_get_memory_ranges(const cm_machine *m, const char **ranges) try {
    if (ranges == nullptr) {
        throw std::invalid_argument("invalid memory range output");
    }
    const auto *cpp_machine = convert_from_c(m);
    const cartesi::machine_memory_range_descrs cpp_ranges = cpp_machine->get_memory_ranges();
    *ranges = cm_set_temp_string(cartesi::to_json(cpp_ranges).dump());
    return cm_result_success();
} catch (...) {
    if (ranges) {
        *ranges = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_receive_cmio_request(const cm_machine *m, uint8_t *cmd, uint16_t *reason, uint8_t *data,
    uint64_t *length) try {
    if (length == nullptr) {
        throw std::invalid_argument("invalid length output");
    }
    const auto *cpp_machine = convert_from_c(m);
    // NOTE(edubart): This can be implemented on top of other APIs,
    // implementing in the C++ machine class would add lot of boilerplate code in all interfaces.
    if (!cpp_machine->read_reg(cartesi::machine::reg::iflags_x) &&
        !cpp_machine->read_reg(cartesi::machine::reg::iflags_y)) {
        throw std::runtime_error{"machine is not yielded"};
    }
    const uint64_t tohost = cpp_machine->read_reg(cartesi::machine::reg::htif_tohost);
    const uint8_t tohost_cmd = cartesi::HTIF_CMD_FIELD(tohost);
    const uint16_t tohost_reason = cartesi::HTIF_REASON_FIELD(tohost);
    const uint32_t tohost_data = cartesi::HTIF_DATA_FIELD(tohost);
    uint64_t data_length{};
    // Reason progress is an special case where it doesn't need to read cmio TX buffer
    if (tohost_cmd == cartesi::HTIF_YIELD_CMD_AUTOMATIC &&
        tohost_reason == cartesi::HTIF_YIELD_AUTOMATIC_REASON_PROGRESS) {
        data_length = sizeof(uint32_t);
        if (data) { // Only actually read when data is not NULL
            if (data_length > *length) {
                throw std::invalid_argument{"data buffer length is too small"};
            }
            memcpy(data, &tohost_data, data_length);
        }
    } else {
        data_length = tohost_data;
        if (data) { // Only actually read when data is not NULL
            if (data_length > *length) {
                throw std::invalid_argument{"data buffer length is too small"};
            }
            cpp_machine->read_memory(cartesi::PMA_CMIO_TX_BUFFER_START, data, data_length);
        }
    }
    if (cmd) {
        *cmd = tohost_cmd;
    }
    if (reason) {
        *reason = tohost_reason;
    }
    if (length) {
        *length = data_length;
    }
    return cm_result_success();
} catch (...) {
    if (cmd) {
        *cmd = 0;
    }
    if (reason) {
        *reason = 0;
    }
    if (length) {
        *length = 0;
    }
    return cm_result_failure();
}

cm_error cm_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->send_cmio_response(reason, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

cm_error cm_log_send_cmio_response(cm_machine *m, uint16_t reason, const uint8_t *data, uint64_t length,
    int32_t log_type, const char **log) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::access_log::type cpp_log_type(log_type);
    cartesi::access_log cpp_log = cpp_machine->log_send_cmio_response(reason, data, length, cpp_log_type);
    *log = cm_set_temp_string(cartesi::to_json(cpp_log).dump());
    return cm_result_success();
} catch (...) {
    if (log) {
        *log = nullptr;
    }
    return cm_result_failure();
}

cm_error cm_verify_send_cmio_response(uint16_t reason, const uint8_t *data, uint64_t length,
    const cm_hash *root_hash_before, const char *log, const cm_hash *root_hash_after) try {
    if (log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }
    const auto cpp_log = // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        cartesi::from_json<cartesi::not_default_constructible<cartesi::access_log>>(log).value();
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    cartesi::machine::verify_send_cmio_response(reason, data, length, cpp_root_hash_before, cpp_log,
        cpp_root_hash_after);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}
