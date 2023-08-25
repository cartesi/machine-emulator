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

#include <json.hpp>

#include "base64.h"
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
template <int I, typename T>
struct new_optional : public std::optional<T> {
    using std::optional<T>::optional;
};

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
template <typename I>
inline std::enable_if_t<std::is_integral_v<I>, bool> contains(const nlohmann::json &j, I i) {
    if constexpr (std::is_signed_v<I>) {
        return j.is_array() && i >= 0 && i < static_cast<I>(j.size());
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

/// \brief Attempts to load a semantic_version object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, semantic_version &value,
    const std::string &path = "params/");

/// \brief Attempts to load a CSR name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine::csr &value, const std::string &path = "params/");

/// \brief Attempts to load an intepreter_break_reason name from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, interpreter_break_reason &value,
    const std::string &path = "params/");

/// \brief Attempts to load an uarch_intepreter_break_reason name from a field in a JSON object
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

/// \brief Attempts to load a rom_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, rom_config &value, const std::string &path = "params/");

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

/// \brief Attempts to load an htif_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, htif_config &value, const std::string &path = "params/");

/// \brief Attempts to load a rollup_config object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, rollup_config &value, const std::string &path = "params/");

/// \brief Attempts to load a std::optional<rollup_config> object from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, std::optional<rollup_config> &optional,
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

/// \brief Attempts to load an array from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
template <typename K, typename T, size_t N>
void ju_get_opt_array_like_field(const nlohmann::json &j, const K &key, std::array<T, N> &value,
    const std::string &path = "params/") {
    if (!contains(j, key)) {
        return;
    }
    const auto &jarray = j[key];
    if (!jarray.is_array()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an array"s);
    }
    if (jarray.size() != N) {
        throw std::invalid_argument(
            "field \""s + path + to_string(key) + "\" should have "s + to_string(N) + " entries"s);
    }
    const auto new_path = path + to_string(key) + "/";
    for (uint64_t i = 0; i < N; ++i) {
        ju_get_field(jarray, i, value[i], new_path);
    }
}

/// \brief Loads an array from a field in a JSON object
/// \tparam K Key type (explicit extern declarations for uint64_t and std::string are provided)
/// \param j JSON object to load from
/// \param key Key to load value from
/// \param value Object to store value
/// \param path Path to j
/// \detail Throws error if field is missing
template <typename K, typename T, size_t N>
void ju_get_array_like_field(const nlohmann::json &j, const K &key, std::array<T, N> &value,
    const std::string &path = "params/") {
    if (!contains(j, key)) {
        throw std::invalid_argument("missing field \""s + path + to_string(key) + "\""s);
    }
    return ju_get_opt_array_like_field(j, key, value, path);
}

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
void to_json(nlohmann::json &j, const ram_config &config);
void to_json(nlohmann::json &j, const rom_config &config);
void to_json(nlohmann::json &j, const tlb_config &config);
void to_json(nlohmann::json &j, const clint_config &config);
void to_json(nlohmann::json &j, const htif_config &config);
void to_json(nlohmann::json &j, const rollup_config &config);
void to_json(nlohmann::json &j, const uarch_processor_config &config);
void to_json(nlohmann::json &j, const uarch_ram_config &config);
void to_json(nlohmann::json &j, const uarch_config &config);
void to_json(nlohmann::json &j, const machine_config &config);
void to_json(nlohmann::json &j, const concurrency_runtime_config &config);
void to_json(nlohmann::json &j, const htif_runtime_config &config);
void to_json(nlohmann::json &j, const machine_runtime_config &runtime);
void to_json(nlohmann::json &j, const machine::csr &csr);

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
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, semantic_version &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, semantic_version &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, machine::csr &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, machine::csr &value,
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
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key,
    not_default_constructible<access_log> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    not_default_constructible<access_log> &value, const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, processor_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, processor_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, rom_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, rom_config &value,
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
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, tlb_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, tlb_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, clint_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, clint_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, htif_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, htif_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, rollup_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key, rollup_config &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const uint64_t &key, std::optional<rollup_config> &value,
    const std::string &base = "params/");
extern template void ju_get_opt_field(const nlohmann::json &j, const std::string &key,
    std::optional<rollup_config> &value, const std::string &base = "params/");
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

} // namespace cartesi

#endif
