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
#include <ios>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
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
static THREAD_LOCAL char last_err_msg[4096];

const char *cm_get_last_error_message() {
    return last_err_msg;
}

void cm_set_last_error_message(const std::string &err_msg) {
    last_err_msg[err_msg.copy(last_err_msg, sizeof(last_err_msg) - 1)] = 0;
}

static char *copy_cstring(const char *str) {
    auto size = strlen(str) + 1;
    auto *copy = new char[size];
    strncpy(copy, str, size);
    return copy;
}

char *string_to_buf(char *dest, size_t maxlen, const std::string &src) {
    using namespace std::string_literals;
    if (src.length() + 1 > maxlen) {
        throw std::runtime_error("cannot store a string of length "s + std::to_string(maxlen) +
            " into a buffer of length "s + std::to_string(src.length() + 1));
    }
    dest[src.copy(dest, maxlen - 1)] = 0;
    return dest;
}

std::string null_to_empty(const char *s) {
    return std::string{s != nullptr ? s : ""};
}

int cm_result_failure() try { throw; } catch (std::exception &e) {
    cm_set_last_error_message(e.what());
    try {
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
    } catch (std::ios_base::failure &ex) {
        return CM_ERROR_SYSTEM_IOS_BASE_FAILURE;
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
    } catch (std::exception &e) {
        return CM_ERROR_EXCEPTION;
    }
} catch (...) {
    cm_set_last_error_message("unknown error");
    return CM_ERROR_UNKNOWN;
}

int cm_result_success() {
    cm_set_last_error_message("");
    return 0;
}

// --------------------------------------------
// String conversion (strdup equivalent with new)
// --------------------------------------------
char *convert_to_c(const std::string &cpp_str) {
    return copy_cstring(cpp_str.c_str());
}

// --------------------------------------------
// Machine pointer conversion functions
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

// ----------------------------------------------
// Hash conversion functions
// ----------------------------------------------

cartesi::machine_merkle_tree::hash_type convert_from_c(const cm_hash *c_hash) {
    if (c_hash == nullptr) {
        throw std::invalid_argument("invalid hash");
    }
    cartesi::machine_merkle_tree::hash_type cpp_hash; // In emulator this is std::array<unsigned char, hash_size>;
    memcpy(cpp_hash.data(), c_hash, sizeof(cm_hash));
    return cpp_hash;
}

std::vector<cartesi::machine_merkle_tree::hash_type> convert_from_c(const cm_hash_array *c_array) {
    auto new_array = std::vector<cartesi::machine_merkle_tree::hash_type>(c_array->count);
    for (size_t i = 0; i < c_array->count; ++i) {
        new_array[i] = convert_from_c(&c_array->entry[i]);
    }
    return new_array;
}

static cm_hash_array *convert_to_c(const std::vector<cartesi::machine_merkle_tree::hash_type> &cpp_array) {
    auto *new_array = new cm_hash_array{};
    new_array->count = cpp_array.size();
    new_array->entry = new cm_hash[cpp_array.size()];
    memset(new_array->entry, 0, sizeof(cm_hash) * new_array->count);
    for (size_t i = 0; i < new_array->count; ++i) {
        memcpy(&new_array->entry[i], static_cast<const uint8_t *>(cpp_array[i].data()), sizeof(cm_hash));
    }
    return new_array;
}

// ----------------------------------------------
// Semantic version conversion functions
// ----------------------------------------------

cm_semantic_version *convert_to_c(const cartesi::semantic_version &cpp_version) {
    auto *new_semantic_version = new cm_semantic_version{};
    new_semantic_version->major = cpp_version.major;
    new_semantic_version->minor = cpp_version.minor;
    new_semantic_version->patch = cpp_version.patch;
    new_semantic_version->pre_release = convert_to_c(cpp_version.pre_release);
    new_semantic_version->build = convert_to_c(cpp_version.build);
    return new_semantic_version;
}

// ----------------------------------------------
// Merkle tree proof conversion functions
// ----------------------------------------------

/// \brief Converts log2_size to index into siblings array
static int cm_log2_size_to_index(int log2_size, int log2_target_size) {
    const int index = log2_size - log2_target_size;
    if (index < 0) {
        throw std::invalid_argument("log2_size can't be smaller than log2_target_size");
    }
    return index;
}

static cm_merkle_tree_proof *convert_to_c(const cartesi::machine_merkle_tree::proof_type &proof) {
    auto *new_merkle_tree_proof = new cm_merkle_tree_proof{};

    new_merkle_tree_proof->log2_root_size = proof.get_log2_root_size();
    new_merkle_tree_proof->log2_target_size = proof.get_log2_target_size();
    new_merkle_tree_proof->target_address = proof.get_target_address();

    memcpy(&new_merkle_tree_proof->root_hash, static_cast<const uint8_t *>(proof.get_root_hash().data()),
        sizeof(cm_hash));
    memcpy(&new_merkle_tree_proof->target_hash, static_cast<const uint8_t *>(proof.get_target_hash().data()),
        sizeof(cm_hash));

    new_merkle_tree_proof->sibling_hashes.count =
        new_merkle_tree_proof->log2_root_size - new_merkle_tree_proof->log2_target_size;
    new_merkle_tree_proof->sibling_hashes.entry = new cm_hash[new_merkle_tree_proof->sibling_hashes.count];
    memset(new_merkle_tree_proof->sibling_hashes.entry, 0,
        sizeof(cm_hash) * new_merkle_tree_proof->sibling_hashes.count);

    for (size_t log2_size = new_merkle_tree_proof->log2_target_size; log2_size < new_merkle_tree_proof->log2_root_size;
         ++log2_size) {
        const int current_index = cm_log2_size_to_index(static_cast<int>(log2_size),
            static_cast<int>(new_merkle_tree_proof->log2_target_size));
        const cartesi::machine_merkle_tree::hash_type sibling_hash =
            proof.get_sibling_hash(static_cast<int>(log2_size));
        memcpy(&(new_merkle_tree_proof->sibling_hashes.entry[current_index]),
            static_cast<const uint8_t *>(sibling_hash.data()), sizeof(cm_hash));
    }

    return new_merkle_tree_proof;
}

// ----------------------------------------------
// Access log conversion functions
// ----------------------------------------------

static CM_ACCESS_TYPE convert_to_c(const cartesi::access_type type) {
    if (type == cartesi::access_type::read) {
        return CM_ACCESS_READ;
    } else {
        return CM_ACCESS_WRITE;
    }
}

static cartesi::access_type convert_from_c(const CM_ACCESS_TYPE c_type) {
    if (c_type == CM_ACCESS_READ) {
        return cartesi::access_type::read;
    } else {
        return cartesi::access_type::write;
    }
}

cartesi::access_log::type convert_from_c(const cm_access_log_type *type) {
    cartesi::access_log::type cpp_type(type->proofs, type->annotations, type->large_data);
    return cpp_type;
}

static cm_access convert_to_c(const cartesi::access &cpp_access) {
    cm_access new_access{};
    new_access.type = convert_to_c(cpp_access.get_type());
    new_access.address = cpp_access.get_address();
    new_access.log2_size = cpp_access.get_log2_size();
    memcpy(&new_access.read_hash, static_cast<const uint8_t *>(cpp_access.get_read_hash().data()), sizeof(cm_hash));
    new_access.read_data = nullptr;
    new_access.read_data_size = 0;
    if (cpp_access.get_read().has_value()) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        const auto &read_value = cpp_access.get_read().value();
        new_access.read_data_size = read_value.size();
        if (new_access.read_data_size > 0) {
            new_access.read_data = new uint8_t[new_access.read_data_size];
            memcpy(new_access.read_data, read_value.data(), new_access.read_data_size);
        }
    }
    if (cpp_access.get_written_hash().has_value()) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        memcpy(&new_access.written_hash, static_cast<const uint8_t *>(cpp_access.get_written_hash().value().data()),
            sizeof(cm_hash));
    } else {
        memset(&new_access.written_hash, 0, sizeof(cm_hash));
    }
    new_access.written_data = nullptr;
    new_access.written_data_size = 0;
    if (cpp_access.get_written().has_value()) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        const auto &written_value = cpp_access.get_written().value();
        new_access.written_data_size = written_value.size();
        if (new_access.written_data_size > 0) {
            new_access.written_data = new uint8_t[new_access.written_data_size];
            memcpy(new_access.written_data, written_value.data(), new_access.written_data_size);
        }
    }

    if (cpp_access.get_sibling_hashes().has_value()) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        new_access.sibling_hashes = convert_to_c(*cpp_access.get_sibling_hashes());
    } else {
        new_access.sibling_hashes = nullptr;
    }

    return new_access;
}

cartesi::access convert_from_c(const cm_access *c_access) {
    cartesi::access cpp_access{};
    cpp_access.set_type(convert_from_c(c_access->type));
    cpp_access.set_log2_size(c_access->log2_size);
    cpp_access.set_address(c_access->address);
    if (c_access->sibling_hashes != nullptr) {
        cpp_access.set_sibling_hashes(convert_from_c(c_access->sibling_hashes));
    }

    cpp_access.set_read_hash(convert_from_c(&c_access->read_hash));
    if (c_access->read_data_size > 0) {
        cpp_access.set_read(cartesi::access_data{c_access->read_data, c_access->read_data + c_access->read_data_size});
    }
    if (c_access->type == CM_ACCESS_WRITE) {
        cpp_access.set_written_hash(convert_from_c(&c_access->written_hash));
    }
    if (c_access->written_data_size > 0) {
        cpp_access.set_written(
            cartesi::access_data{c_access->written_data, c_access->written_data + c_access->written_data_size});
    }
    return cpp_access;
}

static void cm_cleanup_access(cm_access *access) {
    if (access == nullptr) {
        return;
    }
    if (access->sibling_hashes != nullptr) {
        delete[] access->sibling_hashes->entry;
        delete access->sibling_hashes;
    }
    delete[] access->written_data;
    delete[] access->read_data;
}

static CM_BRACKET_TYPE convert_to_c(const cartesi::bracket_type type) {
    if (type == cartesi::bracket_type::begin) {
        return CM_BRACKET_BEGIN;
    } else {
        return CM_BRACKET_END;
    }
}

static cartesi::bracket_type convert_from_c(const CM_BRACKET_TYPE c_type) {
    if (c_type == CM_BRACKET_BEGIN) {
        return cartesi::bracket_type::begin;
    } else {
        return cartesi::bracket_type::end;
    }
}

static cm_bracket_note convert_to_c(const cartesi::bracket_note &cpp_bracket_note) {
    cm_bracket_note new_bracket_note{};
    new_bracket_note.type = convert_to_c(cpp_bracket_note.type);
    new_bracket_note.where = cpp_bracket_note.where;
    new_bracket_note.text = convert_to_c(cpp_bracket_note.text);
    return new_bracket_note;
}

static cartesi::bracket_note convert_from_c(const cm_bracket_note *c_bracket_note) {
    cartesi::bracket_note cpp_bracket_note{};
    cpp_bracket_note.type = convert_from_c(c_bracket_note->type);
    cpp_bracket_note.where = c_bracket_note->where;
    cpp_bracket_note.text = null_to_empty(c_bracket_note->text);
    return cpp_bracket_note;
}

static void cm_cleanup_bracket_note(cm_bracket_note *bracket_note) {
    if (bracket_note == nullptr) {
        return;
    }
    delete[] bracket_note->text;
}

cm_access_log *convert_to_c(const cartesi::access_log &cpp_access_log) {
    auto *new_access_log = new cm_access_log{};

    new_access_log->accesses.count = cpp_access_log.get_accesses().size();
    new_access_log->accesses.entry = new cm_access[new_access_log->accesses.count];
    for (size_t i = 0; i < new_access_log->accesses.count; ++i) {
        new_access_log->accesses.entry[i] = convert_to_c(cpp_access_log.get_accesses()[i]);
    }

    new_access_log->brackets.count = cpp_access_log.get_brackets().size();
    new_access_log->brackets.entry = new cm_bracket_note[new_access_log->brackets.count];
    for (size_t i = 0; i < new_access_log->brackets.count; ++i) {
        new_access_log->brackets.entry[i] = convert_to_c(cpp_access_log.get_brackets()[i]);
    }

    new_access_log->notes.count = cpp_access_log.get_notes().size();
    new_access_log->notes.entry = new const char *[new_access_log->notes.count];
    for (size_t i = 0; i < new_access_log->notes.count; ++i) {
        new_access_log->notes.entry[i] = convert_to_c(cpp_access_log.get_notes()[i]);
    }

    new_access_log->log_type.annotations = cpp_access_log.get_log_type().has_annotations();
    new_access_log->log_type.proofs = cpp_access_log.get_log_type().has_proofs();
    new_access_log->log_type.large_data = cpp_access_log.get_log_type().has_large_data();

    return new_access_log;
}

cartesi::access_log convert_from_c(const cm_access_log *c_acc_log) {
    if (c_acc_log == nullptr) {
        throw std::invalid_argument("invalid access log");
    }

    std::vector<cartesi::access> accesses;
    for (size_t i = 0; i < c_acc_log->accesses.count; ++i) {
        accesses.push_back(convert_from_c(&c_acc_log->accesses.entry[i]));
    }
    std::vector<cartesi::bracket_note> brackets;
    for (size_t i = 0; i < c_acc_log->brackets.count; ++i) {
        brackets.push_back(convert_from_c(&c_acc_log->brackets.entry[i]));
    }

    std::vector<std::string> notes;
    for (size_t i = 0; i < c_acc_log->notes.count; ++i) {
        notes.push_back(null_to_empty(c_acc_log->notes.entry[i]));
    }
    cartesi::access_log new_cpp_acc_log(accesses, brackets, notes, convert_from_c(&c_acc_log->log_type));
    return new_cpp_acc_log;
}

// --------------------------------------------
// Memory range description conversion functions
// --------------------------------------------
cm_memory_range_descr convert_to_c(const cartesi::machine_memory_range_descr &cpp_mrd) {
    cm_memory_range_descr new_mrd{};
    new_mrd.start = cpp_mrd.start;
    new_mrd.length = cpp_mrd.length;
    new_mrd.description = convert_to_c(cpp_mrd.description);
    return new_mrd;
}

cm_memory_range_descr_array *convert_to_c(const cartesi::machine_memory_range_descrs &cpp_mrds) {
    auto *new_mrda = new cm_memory_range_descr_array{};
    new_mrda->count = cpp_mrds.size();
    new_mrda->entry = new cm_memory_range_descr[new_mrda->count];
    for (size_t i = 0; i < new_mrda->count; ++i) {
        new_mrda->entry[i] = convert_to_c(cpp_mrds[i]);
    }
    return new_mrda;
}

// -----------------------------------------------------
// Public API functions for generation of default configs
// -----------------------------------------------------
static inline cartesi::i_virtual_machine *create_virtual_machine(const cartesi::machine_config &c,
    const cartesi::machine_runtime_config &r) {
    return new cartesi::virtual_machine(c, r);
}

static inline cartesi::i_virtual_machine *load_virtual_machine(const char *dir,
    const cartesi::machine_runtime_config &r) {
    return new cartesi::virtual_machine(null_to_empty(dir), r);
}

int cm_create(const char *config, const char *runtime_config, cm_machine **new_machine) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid machine configuration");
    }
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const auto c = cartesi::from_json<cartesi::machine_config>(config);
    const auto r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(create_virtual_machine(c, r));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_load(const char *dir, const char *runtime_config, cm_machine **new_machine) try {
    if (new_machine == nullptr) {
        throw std::invalid_argument("invalid new machine output");
    }
    const auto r = cartesi::from_json<cartesi::machine_runtime_config>(runtime_config);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    *new_machine = reinterpret_cast<cm_machine *>(load_virtual_machine(dir, r));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

void cm_delete_machine(cm_machine *m) {
    if (m == nullptr) {
        return;
    }
    auto *cpp_machine = convert_from_c(m);
    delete cpp_machine;
}

int cm_store(cm_machine *m, const char *dir) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->store(null_to_empty(dir));
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_run(cm_machine *m, uint64_t mcycle_end, CM_BREAK_REASON *break_reason) try {
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

CM_API int cm_read_uarch_halt_flag(const cm_machine *m, bool *val) try {
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_uarch_halt_flag();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

CM_API int cm_set_uarch_halt_flag(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->set_uarch_halt_flag();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

CM_API int cm_reset_uarch(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->reset_uarch();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_log_reset_uarch(cm_machine *m, cm_access_log_type log_type, bool one_based, cm_access_log **access_log) try {
    if (access_log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::access_log::type cpp_log_type{log_type.proofs, log_type.annotations, log_type.large_data};
    cartesi::access_log cpp_access_log = cpp_machine->log_reset_uarch(cpp_log_type, one_based);
    *access_log = convert_to_c(cpp_access_log);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_run_uarch(cm_machine *m, uint64_t uarch_cycle_end, CM_UARCH_BREAK_REASON *break_reason) try {
    auto *cpp_machine = convert_from_c(m);
    const auto status = cpp_machine->run_uarch(uarch_cycle_end);
    if (break_reason) {
        *break_reason = static_cast<CM_UARCH_BREAK_REASON>(status);
    }
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_log_step_uarch(cm_machine *m, cm_access_log_type log_type, bool one_based, cm_access_log **access_log) try {
    if (access_log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::access_log::type cpp_log_type{log_type.proofs, log_type.annotations};
    cartesi::access_log cpp_access_log = cpp_machine->log_step_uarch(cpp_log_type, one_based);
    *access_log = convert_to_c(cpp_access_log);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

void cm_delete_access_log(cm_access_log *acc_log) {
    if (acc_log == nullptr) {
        return;
    }

    for (size_t i = 0; i < acc_log->notes.count; ++i) {
        delete[] acc_log->notes.entry[i];
    }
    delete[] acc_log->notes.entry;
    for (size_t i = 0; i < acc_log->brackets.count; ++i) {
        cm_cleanup_bracket_note(&acc_log->brackets.entry[i]);
    }
    delete[] acc_log->brackets.entry;
    for (size_t i = 0; i < acc_log->accesses.count; ++i) {
        cm_cleanup_access(&acc_log->accesses.entry[i]);
    }
    delete[] acc_log->accesses.entry;
    delete acc_log;
}

int cm_verify_step_uarch_log(const cm_access_log *log, bool one_based) try {
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::machine::verify_step_uarch_log(cpp_log, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_verify_reset_uarch_log(const cm_access_log *log, bool one_based) try {
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::machine::verify_reset_uarch_log(cpp_log, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_verify_step_uarch_state_transition(const cm_hash *root_hash_before, const cm_access_log *log,
    const cm_hash *root_hash_after, bool one_based) try {
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::machine::verify_step_uarch_state_transition(cpp_root_hash_before, cpp_log, cpp_root_hash_after, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_verify_reset_uarch_state_transition(const cm_hash *root_hash_before, const cm_access_log *log,
    const cm_hash *root_hash_after, bool one_based) try {
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::machine::verify_reset_uarch_state_transition(cpp_root_hash_before, cpp_log, cpp_root_hash_after,
        one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_get_proof(const cm_machine *m, uint64_t address, int log2_size, cm_merkle_tree_proof **proof) try {
    if (proof == nullptr) {
        throw std::invalid_argument("invalid proof output");
    }
    const auto *cpp_machine = convert_from_c(m);
    const cartesi::machine_merkle_tree::proof_type cpp_proof = cpp_machine->get_proof(address, log2_size);
    *proof = convert_to_c(cpp_proof);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

void cm_delete_merkle_tree_proof(cm_merkle_tree_proof *proof) {
    if (proof == nullptr) {
        return;
    }
    delete[] proof->sibling_hashes.entry;
    delete proof;
}

void cm_delete_semantic_version(const cm_semantic_version *version) {
    if (version == nullptr) {
        return;
    }

    delete[] version->pre_release;
    delete[] version->build;
    delete version;
}

int cm_get_root_hash(const cm_machine *m, cm_hash *hash) try {
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

int cm_verify_merkle_tree(const cm_machine *m, bool *result) try {
    if (result == nullptr) {
        throw std::invalid_argument("invalid result output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *result = cpp_machine->verify_merkle_tree();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_read_csr(const cm_machine *m, CM_CSR csr, uint64_t *val) try {
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

int cm_write_csr(cm_machine *m, CM_CSR csr, uint64_t val) try {
    auto *cpp_machine = convert_from_c(m);
    auto cpp_csr = static_cast<cartesi::machine::csr>(csr);
    cpp_machine->write_csr(cpp_csr, val);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

uint64_t cm_get_csr_address(CM_CSR csr) {
    auto cpp_csr = static_cast<cartesi::machine::csr>(csr);
    return cartesi::machine::get_csr_address(cpp_csr);
}

int cm_read_word(const cm_machine *m, uint64_t address, uint64_t *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid word output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_word(address);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_read_memory(const cm_machine *m, uint64_t address, unsigned char *data, uint64_t length) try {
    const auto *cpp_machine = convert_from_c(m);
    cpp_machine->read_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_write_memory(cm_machine *m, uint64_t address, const unsigned char *data, size_t length) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->write_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_read_virtual_memory(const cm_machine *m, uint64_t address, unsigned char *data, uint64_t length) try {
    const auto *cpp_machine = convert_from_c(m);
    cpp_machine->read_virtual_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_write_virtual_memory(cm_machine *m, uint64_t address, const unsigned char *data, size_t length) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->write_virtual_memory(address, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_translate_virtual_address(cm_machine *m, uint64_t vaddr, uint64_t *paddr) try {
    const auto *cpp_machine = convert_from_c(m);
    *paddr = cpp_machine->translate_virtual_address(vaddr);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define IMPL_MACHINE_READ_WRITE(field)                                                                                 \
    int cm_read_##field(const cm_machine *m, uint64_t *val) try {                                                      \
        if (val == nullptr) {                                                                                          \
            throw std::invalid_argument("invalid val output");                                                         \
        }                                                                                                              \
        const auto *cpp_machine = convert_from_c(m);                                                                   \
        *val = cpp_machine->read_##field();                                                                            \
        return cm_result_success();                                                                                    \
    } catch (...) {                                                                                                    \
        return cm_result_failure();                                                                                    \
    }                                                                                                                  \
    int cm_write_##field(cm_machine *m, uint64_t val) try {                                                            \
        auto *cpp_machine = convert_from_c(m);                                                                         \
        cpp_machine->write_##field(val);                                                                               \
        return cm_result_success();                                                                                    \
    } catch (...) {                                                                                                    \
        return cm_result_failure();                                                                                    \
    }

// clang-format-off
IMPL_MACHINE_READ_WRITE(mcycle)
IMPL_MACHINE_READ_WRITE(uarch_cycle)
// clang-format-on

int cm_read_iflags_Y(const cm_machine *m, bool *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_iflags_Y();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_reset_iflags_Y(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->reset_iflags_Y();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_set_iflags_Y(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->set_iflags_Y();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_read_iflags_X(const cm_machine *m, bool *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_iflags_X();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_read_iflags_H(const cm_machine *m, bool *val) try {
    if (val == nullptr) {
        throw std::invalid_argument("invalid val output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *val = cpp_machine->read_iflags_H();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_verify_dirty_page_maps(const cm_machine *m, bool *result) try {
    if (result == nullptr) {
        throw std::invalid_argument("invalid result output");
    }
    const auto *cpp_machine = convert_from_c(m);
    *result = cpp_machine->verify_dirty_page_maps();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_get_initial_config(const cm_machine *m, const char **config) try {
    if (config == nullptr) {
        throw std::invalid_argument("invalid config output");
    }
    const auto *cpp_machine = convert_from_c(m);
    const cartesi::machine_config cpp_config = cpp_machine->get_initial_config();
    static THREAD_LOCAL char config_buf[CM_MAX_CONFIG_LENGTH];
    *config = string_to_buf(config_buf, sizeof(config_buf), cartesi::to_json(cpp_config).dump());
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

const char *cm_get_default_config() try {
    const cartesi::machine_config cpp_config = cartesi::machine::get_default_config();
    static THREAD_LOCAL char config_buf[CM_MAX_CONFIG_LENGTH];
    const char *config = string_to_buf(config_buf, sizeof(config_buf), cartesi::to_json(cpp_config).dump());
    cm_result_success();
    return config;
} catch (...) {
    cm_result_failure();
    return nullptr;
}

int cm_replace_memory_range(cm_machine *m, uint64_t start, uint64_t length, bool shared,
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

int cm_destroy(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->destroy();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_snapshot(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->snapshot();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_commit(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->commit();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_rollback(cm_machine *m) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->rollback();
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

CM_API int cm_get_memory_ranges(cm_machine *m, cm_memory_range_descr_array **mrds) try {
    if (mrds == nullptr) {
        throw std::invalid_argument("invalid memory range output");
    }
    auto *cpp_machine = convert_from_c(m);
    *mrds = convert_to_c(cpp_machine->get_memory_ranges());
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

CM_API void cm_delete_memory_range_descr_array(cm_memory_range_descr_array *mrds) {
    if (mrds == nullptr) {
        return;
    }
    for (size_t i = 0; i < mrds->count; ++i) {
        delete[] mrds->entry[i].description;
    }
    delete[] mrds->entry;
    delete mrds;
}

int cm_send_cmio_response(cm_machine *m, uint16_t reason, const unsigned char *data, size_t length) try {
    auto *cpp_machine = convert_from_c(m);
    cpp_machine->send_cmio_response(reason, data, length);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_log_send_cmio_response(cm_machine *m, uint16_t reason, const unsigned char *data, size_t length,
    cm_access_log_type log_type, bool one_based, cm_access_log **access_log) try {
    if (access_log == nullptr) {
        throw std::invalid_argument("invalid access log output");
    }
    auto *cpp_machine = convert_from_c(m);
    cartesi::access_log::type cpp_log_type{log_type.proofs, log_type.annotations, log_type.large_data};
    cartesi::access_log cpp_access_log =
        cpp_machine->log_send_cmio_response(reason, data, length, cpp_log_type, one_based);
    *access_log = convert_to_c(cpp_access_log);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_verify_send_cmio_response_log(uint16_t reason, const unsigned char *data, size_t length,
    const cm_access_log *log, bool one_based) try {
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::machine::verify_send_cmio_response_log(reason, data, length, cpp_log, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}

int cm_verify_send_cmio_response_state_transition(uint16_t reason, const unsigned char *data, size_t length,
    const cm_hash *root_hash_before, const cm_access_log *log, const cm_hash *root_hash_after, bool one_based) try {
    const cartesi::machine::hash_type cpp_root_hash_before = convert_from_c(root_hash_before);
    const cartesi::machine::hash_type cpp_root_hash_after = convert_from_c(root_hash_after);
    const cartesi::access_log cpp_log = convert_from_c(log);
    cartesi::machine::verify_send_cmio_response_state_transition(reason, data, length, cpp_root_hash_before, cpp_log,
        cpp_root_hash_after, one_based);
    return cm_result_success();
} catch (...) {
    return cm_result_failure();
}
