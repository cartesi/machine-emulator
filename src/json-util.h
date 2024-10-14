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

#include <array>
#include <string>
#include <type_traits>

// Disable JSON filesystem support because it is not supported in some targets
#define JSON_HAS_FILESYSTEM 0 // NOLINT(cppcoreguidelines-macro-usage)
#include <json.hpp>

#include "jsonrpc-connection.h"
#include "jsonrpc-virtual-machine.h"
#include "machine-merkle-tree.h"
#include "machine.h"
#include "semantic-version.h"

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

// Optional-like type that allows non-default-constructible types to be constructed by functions that
// receive them by reference
template <typename T>
using not_default_constructible = new_optional<1, T>;

// Forward declaration of generic ju_get_field
template <typename T, typename K>
void ju_get_field(const nlohmann::json &j, const K &key, T &value, const std::string &path = "params/");

// Allows use contains when the index is an integer and j contains an array
template <typename T>
inline std::enable_if_t<std::is_integral_v<T>, bool> contains(const nlohmann::json &j, T i) {
    if constexpr (std::is_signed_v<T>) {
        return j.is_array() && i >= 0 && i < static_cast<T>(j.size());
    } else {
        return j.is_array() && i < j.size();
    }
}

// Overload for case where index is a string and j contains an object
inline bool contains(const nlohmann::json &j, const std::string &s) {
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

/// \brief Attempts to load an uint32_t from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uint32_t &value, const std::string &path = "params/");

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
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine::reg &value, const std::string &path = "params/");

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

/// \brief Attempts to load an concurrency_runtime_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, concurrency_runtime_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load an htif_runtime_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, htif_runtime_config &value,
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
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_merkle_tree::proof_type::hash_type &value,
    const std::string &path = "params/");

/// \brief Attempts to load an Merkle tree proof object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key,
    not_default_constructible<machine_merkle_tree::proof_type> &value, const std::string &path = "params/");

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

/// \brief Attempts to load a tlb_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, tlb_config &value, const std::string &path = "params/");

/// \brief Attempts to load a clint_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, clint_config &value, const std::string &path = "params/");

/// \brief Attempts to load a plic_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, plic_config &value, const std::string &path = "params/");

/// \brief Attempts to load an htif_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, htif_config &value, const std::string &path = "params/");

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

/// \brief Attempts to load an uarch_processor_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_processor_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load an uarch_ram_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_ram_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load an uarch_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_config &value, const std::string &path = "params/");

/// \brief Attempts to load a machine_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_config &value,
    const std::string &path = "params/");

/// \brief Attempts to load a machine_memory_range_descr object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_memory_range_descr &value,
    const std::string &path = "params/");

/// \brief Attempts to load a machine_memory_range_descrs object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_memory_range_descrs &value,
    const std::string &path = "params/");

/// \brief Attempts to load a fork_result object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, fork_result &value, const std::string &path = "params/");

/// \brief Attempts to load a vector from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K, typename A>
void ju_get_opt_vector_like_field(const nlohmann::json &j, const K &key, A &value, const std::string &path) {
    value.clear();
    if (!contains(j, key)) {
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
    if (!contains(j, key)) {
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
    if (contains(j, key)) {
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
    if (!contains(j, key)) {
        throw std::invalid_argument("missing field \""s + path + to_string(key) + "\""s);
    }
    ju_get_opt_field(j, key, value, path);
}

/// \brief Encodes binary data into base64
/// \param data Pointer to start of binary data
/// \param length Length of data
/// \returns Encoded data
std::string encode_base64(const unsigned char *data, uint64_t length);

/// \brief Encodes a hash as a base64 string
/// \param hash Hash to encode
/// \returns Encoded data
std::string encode_base64(const machine_merkle_tree::hash_type &hash);

/// \brief Encodes an access_data object as a base64 string
/// \param data Access data to encode
/// \returns Encoded data
std::string encode_base64(const access_data &data);

// Automatic conversion functions from Cartesi types to nlohmann::json
void to_json(nlohmann::json &j, const access_log::type &log_type);
void to_json(nlohmann::json &j, const machine_merkle_tree::hash_type &h);
void to_json(nlohmann::json &j, const std::vector<machine_merkle_tree::hash_type> &hs);
void to_json(nlohmann::json &j, const machine_merkle_tree::proof_type &p);
void to_json(nlohmann::json &j, const access &a);
void to_json(nlohmann::json &j, const bracket_note &b);
void to_json(nlohmann::json &j, const std::vector<bracket_note> &bs);
void to_json(nlohmann::json &j, const std::vector<access> &as);
void to_json(nlohmann::json &j, const access_log &log);
void to_json(nlohmann::json &j, const memory_range_config &config);
void to_json(nlohmann::json &j, const processor_config &config);
void to_json(nlohmann::json &j, const flash_drive_configs &fs);
void to_json(nlohmann::json &j, const virtio_device_config &config);
void to_json(nlohmann::json &j, const virtio_configs &vs);
void to_json(nlohmann::json &j, const ram_config &config);
void to_json(nlohmann::json &j, const dtb_config &config);
void to_json(nlohmann::json &j, const tlb_config &config);
void to_json(nlohmann::json &j, const clint_config &config);
void to_json(nlohmann::json &j, const plic_config &config);
void to_json(nlohmann::json &j, const htif_config &config);
void to_json(nlohmann::json &j, const cmio_config &config);
void to_json(nlohmann::json &j, const uarch_processor_config &config);
void to_json(nlohmann::json &j, const uarch_ram_config &config);
void to_json(nlohmann::json &j, const uarch_config &config);
void to_json(nlohmann::json &j, const machine_config &config);
void to_json(nlohmann::json &j, const concurrency_runtime_config &config);
void to_json(nlohmann::json &j, const htif_runtime_config &config);
void to_json(nlohmann::json &j, const machine_runtime_config &runtime);
void to_json(nlohmann::json &j, const machine::reg &reg);
void to_json(nlohmann::json &j, const machine_memory_range_descrs &mrds);
void to_json(nlohmann::json &j, const fork_result &fork_result);
void to_json(nlohmann::json &j, const semantic_version &version);

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
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine::reg &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, machine::reg &value,
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
extern template void ju_get_opt_field(const nlohmann::json &j, const bool &key, htif_runtime_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, htif_runtime_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine_runtime_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, machine_runtime_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key,
    machine_merkle_tree::proof_type::hash_type &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    machine_merkle_tree::proof_type::hash_type &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key,
    not_default_constructible<machine_merkle_tree::proof_type> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    not_default_constructible<machine_merkle_tree::proof_type> &value, const std::string &base = "params/");
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
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, tlb_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, tlb_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, clint_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, clint_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, plic_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, plic_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, htif_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, htif_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, cmio_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, cmio_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, std::optional<cmio_config> &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    std::optional<cmio_config> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uarch_processor_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uarch_processor_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uarch_ram_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uarch_ram_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, uarch_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, uarch_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, machine_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine_memory_range_descr &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    machine_memory_range_descr &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine_memory_range_descrs &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    machine_memory_range_descrs &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, fork_result &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, fork_result &value,
    const std::string &base = "params/");

template <typename T>
nlohmann::json to_json(const T &v) {
    nlohmann::json j;
    to_json(j, v);
    return j;
}

template <typename T>
T from_json(const char *s) {
    T value{};
    if (s) {
        const nlohmann::json j = nlohmann::json{{"value", nlohmann::json::parse(s)}};
        ju_get_field(j, "value"s, value, ""s);
    }
    return value;
}

} // namespace cartesi

#endif
