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

#ifndef JSON_UTIL_H
#define JSON_UTIL_H

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <json.hpp>

#include "access-log.h"
#include "address-range-description.h"
#include "back-merkle-tree.h"
#include "bracket-note.h"
#include "hash-tree-proof.h"
#include "hash-tree-stats.h"
#include "interpret.h"
#include "jsonrpc-fork-result.h"
#include "machine-config.h"
#include "machine-hash.h"
#include "machine-reg.h"
#include "machine-runtime-config.h"
#include "mcycle-root-hashes.h"
#include "page-hash-tree-cache-stats.h"
#include "semantic-version.h"
#include "shadow-registers.h"
#include "shadow-uarch-state.h"
#include "uarch-cycle-root-hashes.h"
#include "uarch-interpret.h"
#include "variant-hasher.h"

namespace cartesi {

using namespace std::string_literals;

// Allow using cartesi::to_string when the input type is already a string
using std::to_string;
std::string to_string(const std::string &s);
std::string to_string(const char *s);

// Generate a new optional-like type
template <int N, typename T>
struct new_optional : public std::optional<T> {};

// Optional-like type used by parse_args function to identify an optional parameter
template <typename T>
using optional_param = new_optional<0, T>;

/// \brief Type trait to test if a type has been encapsulated in an optional_param
/// \tparam T type to test
/// \details This is the default case
template <typename T>
struct is_optional_param : std::false_type {};

/// \brief Type trait to test if a type has been encapsulated in an optional_param
/// \tparam T type to test
/// \details This is the encapsulated case
template <typename T>
struct is_optional_param<cartesi::optional_param<T>> : std::true_type {};

/// \brief Shortcut to the type trait to test if a type has been encapsulated in an optional_param
/// \tparam T type to test
template <typename T>
inline constexpr bool is_optional_param_v = is_optional_param<T>::value;

// Optional-like type that allows non-default-constructible types to be constructed by functions that
// receive them by reference
template <typename T>
using not_default_constructible = new_optional<1, T>;

// Forward declaration of generic ju_get_field
template <typename T, typename K>
void ju_get_field(const nlohmann::json &j, const K &key, T &value, const std::string &path = "params/");

// Allows use contains when the index is an integer and j contains an array
template <typename T>
inline bool contains(const nlohmann::json &j, T i, const std::string &path)
    requires(std::is_integral_v<T>)
{
    if (!j.empty() && !j.is_array()) {
        throw std::invalid_argument("\""s + path + "\" not an array");
    }
    if constexpr (std::is_signed_v<T>) {
        return i >= 0 && i < static_cast<T>(j.size());
    } else {
        return i < j.size();
    }
}

// Overload for case where index is a string and j contains an object
inline bool contains(const nlohmann::json &j, const std::string &s, const std::string &path) {
    if (!j.empty() && !j.is_object()) {
        throw std::invalid_argument("\""s + path + "\" not an object");
    }
    return j.contains(s);
}

/// \brief Attempts to load a string from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, std::string &value, const std::string &path = "params/");

/// \brief Attempts to load a bool from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, bool &value, const std::string &path = "params/");

/// \brief Attempts to load an uint64_t from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uint64_t &value, const std::string &path = "params/");

/// \brief Attempts to load an int64_t from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, int64_t &value, const std::string &path = "params/");

/// \brief Attempts to load an uint32_t from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uint32_t &value, const std::string &path = "params/");

/// \brief Attempts to load an int32_t from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, int32_t &value, const std::string &path = "params/");

/// \brief Attempts to load an uint16_t from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uint16_t &value, const std::string &path = "params/");

/// \brief Attempts to load a semantic_version object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, semantic_version &value,
    const std::string &path = "params/");

/// \brief Attempts to load a register name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_reg &value, const std::string &path = "params/");

/// \brief Attempts to load an sharing_mode name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, sharing_mode &value, const std::string &path = "params/");

/// \brief Attempts to load an interpreter_break_reason name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, interpreter_break_reason &value,
    const std::string &path = "params/");

/// \brief Attempts to load an uarch_interpreter_break_reason name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_interpreter_break_reason &value,
    const std::string &path = "params/");

/// \brief Attempts to load a console_output_destination name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, console_output_destination &value,
    const std::string &path = "params/");

/// \brief Attempts to load a console_flush_mode name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, console_flush_mode &value,
    const std::string &path = "params/");

/// \brief Attempts to load a console_input_source name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, console_input_source &value,
    const std::string &path = "params/");

/// \brief Attempts to load a console_runtime_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, console_runtime_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load an concurrency_runtime_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, concurrency_runtime_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load an machine_runtime_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_runtime_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load a hash from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_hash &value, const std::string &path = "params/");

/// \brief Attempts to load a hash from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, std::optional<machine_hash> &optional,
    const std::string &path = "params/");

/// \brief Attempts to load a hash-tree proof object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, not_default_constructible<hash_tree_proof> &value,
    const std::string &path = "params/");

/// \brief Attempts to load a page_hash_tree_cache_stats object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, page_hash_tree_cache_stats &value,
    const std::string &path = "params/");

/// \brief Attempts to load a hash_tree_stats object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, hash_tree_stats &value,
    const std::string &path = "params/");

/// \brief Attempts to load an access_type name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, access_type &value, const std::string &path = "params/");

/// \brief Attempts to load an access_data object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, access_data &data, const std::string &path = "params/");

/// \brief Attempts to load an access_data object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, std::optional<access_data> &optional,
    const std::string &path = "params/");

/// \brief Attempts to load an access object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, access &access, const std::string &path = "params/");

/// \brief Attempts to load a bracket_type name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, bracket_type &value, const std::string &path = "params/");

/// \brief Attempts to load a bracket_note object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, bracket_note &value, const std::string &path = "params/");

/// \brief Attempts to load an access_log type object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, not_default_constructible<access_log::type> &optional,
    const std::string &path = "params/");

/// \brief Attempts to load an access_log object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, not_default_constructible<access_log> &optional,
    const std::string &path = "params/");

/// \brief Attempts to load a registers_state object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, registers_state &value,
    const std::string &path = "params/");

/// \brief Attempts to load a processor_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, processor_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load a dtb_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, dtb_config &value, const std::string &path = "params/");

/// \brief Attempts to load a ram_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, ram_config &value, const std::string &path = "params/");

/// \brief Attempts to load a memory_range_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, memory_range_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load a backing_store_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, backing_store_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load a backing_store_config_only object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, backing_store_config_only &value,
    const std::string &path = "params/");

/// \brief Attempts to load a flash_drive_configs object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, flash_drive_configs &value,
    const std::string &path = "params/");

/// \brief Attempts to load a virtio_device_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, virtio_device_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load an virtio_configs object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, virtio_configs &value,
    const std::string &path = "params/");

/// \brief Attempts to load a iflags_state object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, iflags_state &value, const std::string &path = "params/");

/// \brief Attempts to load a clint_state object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, clint_state &value, const std::string &path = "params/");

/// \brief Attempts to load a plic_state object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, plic_state &value, const std::string &path = "params/");

/// \brief Attempts to load an htif_state object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, htif_state &value, const std::string &path = "params/");

/// \brief Attempts to load a cmio_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, cmio_config &value, const std::string &path = "params/");

/// \brief Attempts to load a std::optional<cmio_config> object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, std::optional<cmio_config> &optional,
    const std::string &path = "params/");

/// \brief Attempts to load an uarch_registers_state object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_registers_state &value,
    const std::string &path = "params/");

/// \brief Attempts to load an uarch_processor_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_processor_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load an uarch_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_config &value, const std::string &path = "params/");

/// \brief Attempts to load a hash_function_type object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, hash_function_type &value,
    const std::string &path = "params/");

/// \brief Attempts to load an hash_tree_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, hash_tree_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load a machine_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load a address_range_description object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, address_range_description &value,
    const std::string &path = "params/");

/// \brief Attempts to load a address_range_descriptions object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, address_range_descriptions &value,
    const std::string &path = "params/");

/// \brief Attempts to load a fork_result object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, fork_result &value, const std::string &path = "params/");

/// \brief Attempts to load an mcycle_root_hashes object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, mcycle_root_hashes &value,
    const std::string &path = "params/");

/// \brief Attempts to load an uarch_cycle_root_hashes object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_cycle_root_hashes &value,
    const std::string &path = "params/");

/// \brief Attempts to load an std::optional<back_merkle_tree> object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, std::optional<back_merkle_tree> &value,
    const std::string &path = "params/");

/// \brief Attempts to load a vector from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K, typename A>
void ju_get_opt_vector_like_field(const nlohmann::json &j, const K &key, A &value, const std::string &path) {
    value.clear();
    if (!contains(j, key, path)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_array()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an array");
    }
    const auto new_path = path + to_string(key) + "/";
    for (uint64_t key = 0; key < jk.size(); ++key) {
        if constexpr (std::is_default_constructible_v<typename A::value_type>) {
            typename A::value_type item;
            ju_get_field(jk, key, item, new_path);
            value.push_back(std::move(item));
        } else {
            not_default_constructible<typename A::value_type> item;
            ju_get_field(jk, key, item, new_path);
            value.push_back(std::move(item).value());
        }
    }
}

/// \brief Loads a vector from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
/// \detail Throws error if field is missing
template <typename K, typename A>
void ju_get_vector_like_field(const nlohmann::json &j, const K &key, A &value, const std::string &path = "params/") {
    if (!contains(j, key, path)) {
        throw std::invalid_argument("missing field \""s + path + to_string(key) + "\""s);
    }
    return ju_get_opt_vector_like_field(j, key, value, path);
}

/// \brief Attempts to load an optional_param from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename T, typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, optional_param<T> &value,
    const std::string &path = "params/") {
    if (contains(j, key, path)) {
        value.emplace();
        ju_get_opt_field(j, key, value.value(), path);
    }
}

/// \brief Loads an object from a field in a JSON object.
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
/// \detail Throws error if field is missing
template <typename T, typename K>
void ju_get_field(const nlohmann::json &j, const K &key, T &value, const std::string &path) {
    if constexpr (!is_optional_param_v<T>) {
        if (!contains(j, key, path)) {
            throw std::invalid_argument("missing field \""s + path + to_string(key) + "\""s);
        }
    }
    ju_get_opt_field(j, key, value, path);
}

template <typename T>
class override_to_json {
    const T &m_t; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    explicit override_to_json(const T &t) : m_t(t) {}
    const T &get() const {
        return m_t;
    }
};

using base64_machine_hash = override_to_json<machine_hash>;
using base64_machine_hashes = override_to_json<machine_hashes>;

// Automatic conversion functions from Cartesi types to nlohmann::json
void to_json(nlohmann::json &j, const access_log::type &log_type);
void to_json(nlohmann::json &j, const base64_machine_hash &h);
void to_json(nlohmann::json &j, const base64_machine_hashes &hs);
void to_json(nlohmann::json &j, const hash_tree_proof &p);
void to_json(nlohmann::json &j, const page_hash_tree_cache_stats &s);
void to_json(nlohmann::json &j, const hash_tree_stats &s);
void to_json(nlohmann::json &j, const access &a);
void to_json(nlohmann::json &j, const bracket_note &b);
void to_json(nlohmann::json &j, const std::vector<bracket_note> &bs);
void to_json(nlohmann::json &j, const std::vector<access> &as);
void to_json(nlohmann::json &j, const access_log &log);
void to_json(nlohmann::json &j, const interpreter_break_reason &break_reason);
void to_json(nlohmann::json &j, const uarch_interpreter_break_reason &break_reason);
void to_json(nlohmann::json &j, const backing_store_config &config);
void to_json(nlohmann::json &j, const backing_store_config_only &config);
void to_json(nlohmann::json &j, const memory_range_config &config);
void to_json(nlohmann::json &j, const registers_state &config);
void to_json(nlohmann::json &j, const processor_config &config);
void to_json(nlohmann::json &j, const flash_drive_configs &fs);
void to_json(nlohmann::json &j, const virtio_device_config &config);
void to_json(nlohmann::json &j, const virtio_configs &vs);
void to_json(nlohmann::json &j, const ram_config &config);
void to_json(nlohmann::json &j, const dtb_config &config);
void to_json(nlohmann::json &j, const iflags_state &config);
void to_json(nlohmann::json &j, const clint_state &config);
void to_json(nlohmann::json &j, const plic_state &config);
void to_json(nlohmann::json &j, const htif_state &config);
void to_json(nlohmann::json &j, const cmio_config &config);
void to_json(nlohmann::json &j, const uarch_registers_state &config);
void to_json(nlohmann::json &j, const uarch_processor_config &config);
void to_json(nlohmann::json &j, const uarch_config &config);
void to_json(nlohmann::json &j, const hash_tree_config &config);
void to_json(nlohmann::json &j, const machine_config &config);
void to_json(nlohmann::json &j, const console_output_destination &dest);
void to_json(nlohmann::json &j, const console_flush_mode &mode);
void to_json(nlohmann::json &j, const console_input_source &source);
void to_json(nlohmann::json &j, const console_runtime_config &config);
void to_json(nlohmann::json &j, const concurrency_runtime_config &config);
void to_json(nlohmann::json &j, const machine_runtime_config &runtime);
void to_json(nlohmann::json &j, const machine_reg &reg);
void to_json(nlohmann::json &j, const sharing_mode &sharing);
void to_json(nlohmann::json &j, const address_range_description &mrd);
void to_json(nlohmann::json &j, const address_range_descriptions &mrds);
void to_json(nlohmann::json &j, const fork_result &fork_result);
void to_json(nlohmann::json &j, const semantic_version &version);
void to_json(nlohmann::json &j, const std::vector<uint64_t> &uints);
void to_json(nlohmann::json &j, const mcycle_root_hashes &result);
void to_json(nlohmann::json &j, const uarch_cycle_root_hashes &result);
void to_json(nlohmann::json &j, const back_merkle_tree &back_tree);

template <typename T>
void to_json(nlohmann::json &j, const std::optional<T> &v) {
    if (v.has_value()) {
        to_json(j, *v);
    } else {
        j = nullptr;
    }
}

// Extern template declarations
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, std::string &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, std::string &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, bool &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, bool &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uint64_t &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uint64_t &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uint32_t &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uint16_t &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, semantic_version &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, semantic_version &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine_reg &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, machine_reg &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, sharing_mode &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, sharing_mode &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, interpreter_break_reason &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, interpreter_break_reason &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key,
    uarch_interpreter_break_reason &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    uarch_interpreter_break_reason &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, concurrency_runtime_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    concurrency_runtime_config &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine_runtime_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, machine_runtime_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine_hash &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, machine_hash &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key,
    not_default_constructible<hash_tree_proof> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    not_default_constructible<hash_tree_proof> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, page_hash_tree_cache_stats &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    page_hash_tree_cache_stats &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, hash_tree_stats &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, hash_tree_stats &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, access_type &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, access_type &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, access_data &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, access_data &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, access &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, access &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, bracket_type &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, bracket_type &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, bracket_note &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, bracket_note &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key,
    not_default_constructible<access_log::type> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    not_default_constructible<access_log::type> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uint32_t &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uint16_t &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key,
    not_default_constructible<access_log> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    not_default_constructible<access_log> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, registers_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, registers_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, processor_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, processor_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, dtb_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, dtb_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, ram_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, ram_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, memory_range_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, memory_range_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, backing_store_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, backing_store_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, backing_store_config_only &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, backing_store_config_only &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, flash_drive_configs &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, flash_drive_configs &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, virtio_device_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, virtio_device_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, virtio_configs &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, virtio_configs &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, iflags_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, iflags_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, clint_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, clint_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, plic_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, plic_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, htif_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, htif_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, cmio_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, cmio_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, std::optional<cmio_config> &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    std::optional<cmio_config> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uarch_registers_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uarch_registers_state &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uarch_processor_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uarch_processor_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uarch_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uarch_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, hash_tree_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, hash_tree_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, machine_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, address_range_description &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, address_range_description &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, address_range_descriptions &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    address_range_descriptions &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, fork_result &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, fork_result &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, mcycle_root_hashes &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, mcycle_root_hashes &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uarch_cycle_root_hashes &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uarch_cycle_root_hashes &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key,
    std::optional<back_merkle_tree> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    std::optional<back_merkle_tree> &value, const std::string &base = "params/");

template <typename T>
nlohmann::json to_json(const T &v) {
    nlohmann::json j;
    to_json(j, v);
    return j;
}

template <typename T>
T from_json(const char *s, const char *path) {
    T value{};
    if (s) {
        const nlohmann::json j = nlohmann::json{{path, nlohmann::json::parse(s)}};
        ju_get_field(j, std::string{path}, value, ""s);
    }
    return value;
}

} // namespace cartesi

#endif
