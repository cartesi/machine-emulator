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

#include <climits>
#include <exception>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>

#include "json-util.h"

namespace cartesi {

std::string to_string(const std::string &s) {
    return s;
}

std::string to_string(const char *s) {
    return s;
}

std::string encode_base64(const unsigned char *data, uint64_t length) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string input(reinterpret_cast<const char *>(data), length);
    return encode_base64(input);
}

std::string encode_base64(const machine_merkle_tree::hash_type &hash) {
    return encode_base64(hash.data(), hash.size());
}

std::string encode_base64(const access_data &data) {
    return encode_base64(data.data(), data.size());
}

/// \brief Converts between a CSR name and a CSR index
/// \param name CSR name
/// \returns The CSR index
static auto csr_from_name(const std::string &name) {
    using csr = machine::csr;
    const static std::unordered_map<std::string, csr> g_csr_name = {
        {"pc", csr::pc},
        {"fcsr", csr::fcsr},
        {"mvendorid", csr::mvendorid},
        {"marchid", csr::marchid},
        {"mimpid", csr::mimpid},
        {"mcycle", csr::mcycle},
        {"icycleinstret", csr::icycleinstret},
        {"mstatus", csr::mstatus},
        {"mtvec", csr::mtvec},
        {"mscratch", csr::mscratch},
        {"mepc", csr::mepc},
        {"mcause", csr::mcause},
        {"mtval", csr::mtval},
        {"misa", csr::misa},
        {"mie", csr::mie},
        {"mip", csr::mip},
        {"medeleg", csr::medeleg},
        {"mideleg", csr::mideleg},
        {"mcounteren", csr::mcounteren},
        {"menvcfg", csr::menvcfg},
        {"stvec", csr::stvec},
        {"sscratch", csr::sscratch},
        {"sepc", csr::sepc},
        {"scause", csr::scause},
        {"stval", csr::stval},
        {"satp", csr::satp},
        {"scounteren", csr::scounteren},
        {"senvcfg", csr::senvcfg},
        {"ilrsc", csr::ilrsc},
        {"iflags", csr::iflags},
        {"clint_mtimecmp", csr::clint_mtimecmp},
        {"htif_tohost", csr::htif_tohost},
        {"htif_fromhost", csr::htif_fromhost},
        {"htif_ihalt", csr::htif_ihalt},
        {"htif_iconsole", csr::htif_iconsole},
        {"htif_iyield", csr::htif_iyield},
        {"uarch_pc", csr::uarch_pc},
        {"uarch_cycle", csr::uarch_cycle},
        {"uarch_ram_length", csr::uarch_ram_length},
    };
    auto got = g_csr_name.find(name);
    if (got == g_csr_name.end()) {
        throw std::domain_error{"invalid csr"};
    }
    return got->second;
}

static auto csr_to_name(machine::csr reg) {
    using csr = machine::csr;
    switch (reg) {
        case csr::pc:
            return "pc";
        case csr::fcsr:
            return "fcsr";
        case csr::mvendorid:
            return "mvendorid";
        case csr::marchid:
            return "marchid";
        case csr::mimpid:
            return "mimpid";
        case csr::mcycle:
            return "mcycle";
        case csr::icycleinstret:
            return "icycleinstret";
        case csr::mstatus:
            return "mstatus";
        case csr::mtvec:
            return "mtvec";
        case csr::mscratch:
            return "mscratch";
        case csr::mepc:
            return "mepc";
        case csr::mcause:
            return "mcause";
        case csr::mtval:
            return "mtval";
        case csr::misa:
            return "misa";
        case csr::mie:
            return "mie";
        case csr::mip:
            return "mip";
        case csr::medeleg:
            return "medeleg";
        case csr::mideleg:
            return "mideleg";
        case csr::mcounteren:
            return "mcounteren";
        case csr::menvcfg:
            return "menvcfg";
        case csr::stvec:
            return "stvec";
        case csr::sscratch:
            return "sscratch";
        case csr::sepc:
            return "sepc";
        case csr::scause:
            return "scause";
        case csr::stval:
            return "stval";
        case csr::satp:
            return "satp";
        case csr::scounteren:
            return "scounteren";
        case csr::senvcfg:
            return "senvcfg";
        case csr::ilrsc:
            return "ilrsc";
        case csr::iflags:
            return "iflags";
        case csr::clint_mtimecmp:
            return "clint_mtimecmp";
        case csr::htif_tohost:
            return "htif_tohost";
        case csr::htif_fromhost:
            return "htif_fromhost";
        case csr::htif_ihalt:
            return "htif_ihalt";
        case csr::htif_iconsole:
            return "htif_iconsole";
        case csr::htif_iyield:
            return "htif_iyield";
        case csr::uarch_pc:
            return "uarch_pc";
        case csr::uarch_cycle:
            return "uarch_cycle";
        case csr::uarch_ram_length:
            return "uarch_ram_length";
        default:
            throw std::domain_error{"invalid csr"};
            break;
    }
    return "";
}

interpreter_break_reason interpreter_break_reason_from_name(const std::string &name) {
    using ibr = interpreter_break_reason;
    const static std::unordered_map<std::string, ibr> g_ibr_name = {{"failed", ibr::failed}, {"halted", ibr::halted},
        {"yielded_manually", ibr::yielded_manually}, {"yielded_automatically", ibr::yielded_automatically},
        {"reached_target_mcycle", ibr::reached_target_mcycle}};
    auto got = g_ibr_name.find(name);
    if (got == g_ibr_name.end()) {
        throw std::domain_error{"invalid interpreter break reason"};
    }
    return got->second;
}

uarch_interpreter_break_reason uarch_interpreter_break_reason_from_name(const std::string &name) {
    using uibr = uarch_interpreter_break_reason;
    if (name == "reached_target_cycle") {
        return uibr::reached_target_cycle;
    }
    if (name == "uarch_halted") {
        return uibr::uarch_halted;
    }
    throw std::domain_error{"invalid uarch interpreter break reason"};
}

static std::string access_type_name(access_type at) {
    switch (at) {
        case access_type::read:
            return "read";
        case access_type::write:
            return "write";
    }
    throw std::domain_error{"invalid access type"};
}

static std::string bracket_type_name(bracket_type bt) {
    switch (bt) {
        case bracket_type::begin:
            return "begin";
        case bracket_type::end:
            return "end";
    }
    throw std::domain_error{"invalid bracket type"};
}

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, std::string &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    value = jk.template get<std::string>();
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, std::string &value,
    const std::string &path);
template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, std::string &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, bool &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_boolean()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a Boolean");
    }
    value = jk.template get<bool>();
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, bool &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, bool &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uint64_t &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_number_integer() && !jk.is_number_unsigned() && !jk.is_number_float()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an unsigned integer");
    }
    if (jk.is_number_float()) {
        auto f = jk.template get<nlohmann::json::number_float_t>();
        if (f < 0 || std::fmod(f, static_cast<nlohmann::json::number_float_t>(1.0)) != 0 ||
            f > static_cast<nlohmann::json::number_float_t>(UINT64_MAX)) {
            throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an unsigned integer");
        }
        value = static_cast<uint64_t>(f);
        return;
    }
    if (jk.is_number_unsigned()) {
        value = jk.template get<uint64_t>();
        return;
    }
    auto i = jk.template get<nlohmann::json::number_integer_t>();
    if (i < 0) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an unsigned integer");
    }
    value = static_cast<uint64_t>(i);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, uint64_t &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, uint64_t &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uint32_t &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    uint64_t value64 = 0;
    ju_get_field(j, key, value64, path);
    if (value64 > UINT32_MAX) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" out of range");
    }
    value = static_cast<uint32_t>(value64);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, uint32_t &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, uint32_t &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, semantic_version &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_object()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a semantic version");
    }
    const auto new_path = path + to_string(key) + "/";
    ju_get_field(jk, "major"s, value.major, new_path);
    ju_get_field(jk, "minor"s, value.minor, new_path);
    ju_get_field(jk, "patch"s, value.patch, new_path);
    ju_get_field(jk, "pre_release"s, value.pre_release, new_path);
    ju_get_field(jk, "build"s, value.build, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, semantic_version &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, semantic_version &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine::csr &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    value = csr_from_name(jk.template get<std::string>());
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, machine::csr &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, machine::csr &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, interpreter_break_reason &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    value = interpreter_break_reason_from_name(jk.template get<std::string>());
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, interpreter_break_reason &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    interpreter_break_reason &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_interpreter_break_reason &value,
    const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    value = uarch_interpreter_break_reason_from_name(jk.template get<std::string>());
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key,
    uarch_interpreter_break_reason &value, const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    uarch_interpreter_break_reason &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, concurrency_runtime_config &value,
    const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    ju_get_opt_field(j[key], "update_merkle_tree"s, value.update_merkle_tree, path + to_string(key) + "/");
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key,
    concurrency_runtime_config &value, const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    concurrency_runtime_config &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, htif_runtime_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    ju_get_opt_field(j[key], "no_console_putchar"s, value.no_console_putchar, path + to_string(key) + "/");
}

template void ju_get_opt_field<bool>(const nlohmann::json &j, const bool &key, htif_runtime_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, htif_runtime_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_runtime_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    ju_get_field(j[key], "concurrency"s, value.concurrency, path + to_string(key) + "/");
    ju_get_field(j[key], "htif"s, value.htif, path + to_string(key) + "/");
    ju_get_opt_field(j[key], "skip_root_hash_check"s, value.skip_root_hash_check, path + to_string(key) + "/");
    ju_get_opt_field(j[key], "skip_version_check"s, value.skip_version_check, path + to_string(key) + "/");
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, machine_runtime_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    machine_runtime_config &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_merkle_tree::proof_type::hash_type &value,
    const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    std::string bin = decode_base64(jk.template get<std::string>());
    if (bin.size() != value.size()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a base64-encoded 256-bit hash");
    }
    std::copy(bin.begin(), bin.end(), value.data());
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key,
    machine_merkle_tree::proof_type::hash_type &value, const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    machine_merkle_tree::proof_type::hash_type &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key,
    not_default_constructible<machine_merkle_tree::proof_type> &value, const std::string &path) {
    value = {};
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    const auto new_path = path + to_string(key) + "/";
    uint64_t log2_root_size = 0;
    ju_get_field(jk, "log2_root_size"s, log2_root_size, new_path);
    if (log2_root_size > INT_MAX) {
        throw std::domain_error("field \""s + new_path + "log2_root_size\" is out of bounds");
    }
    uint64_t log2_target_size = 0;
    ju_get_field(jk, "log2_target_size"s, log2_target_size, new_path);
    if (log2_root_size > INT_MAX) {
        throw std::domain_error("field \""s + new_path + "log2_target_size\" is out of bounds");
    }
    value.emplace(static_cast<int>(log2_root_size), static_cast<int>(log2_target_size));
    auto &proof = value.value();
    machine_merkle_tree::proof_type::address_type target_address = 0;
    ju_get_field(jk, "target_address"s, target_address, new_path);
    proof.set_target_address(target_address);
    machine_merkle_tree::proof_type::hash_type target_hash;
    ju_get_field(jk, "target_hash"s, target_hash, new_path);
    proof.set_target_hash(target_hash);
    machine_merkle_tree::proof_type::hash_type root_hash;
    ju_get_field(jk, "root_hash"s, root_hash, new_path);
    proof.set_root_hash(root_hash);
    if (!contains(jk, "sibling_hashes")) {
        throw std::invalid_argument("missing field \""s + new_path + "sibling_hashes\""s);
    }
    const auto &sh = jk["sibling_hashes"];
    if (!sh.is_array()) {
        throw std::invalid_argument("field \""s + new_path + "sibling_hashes\" not an array"s);
    }
    const auto sibling_hashes_base = path + "sibling_hashes/";
    for (int log2_size = proof.get_log2_root_size() - 1; log2_size >= proof.get_log2_target_size(); --log2_size) {
        machine_merkle_tree::proof_type::hash_type sibling_hash;
        ju_get_field(sh, static_cast<uint64_t>(proof.get_log2_root_size() - 1 - log2_size), sibling_hash,
            sibling_hashes_base);
        proof.set_sibling_hash(sibling_hash, log2_size);
    }
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key,
    not_default_constructible<machine_merkle_tree::proof_type> &value, const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    not_default_constructible<machine_merkle_tree::proof_type> &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, access_type &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    const auto &v = jk.template get<std::string>();
    if (v == "read") {
        value = access_type::read;
        return;
    }
    if (v == "write") {
        value = access_type::write;
        return;
    }
    throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an access type");
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, access_type &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, access_type &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, access_data &data, const std::string &path) {
    data.clear();
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    const auto &bin = decode_base64(jk.template get<std::string>());
    std::copy(bin.begin(), bin.end(), std::back_inserter(data));
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, access_data &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, access_data &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, access &access, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_object()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an object");
    }
    const auto new_path = path + to_string(key) + "/";
    access_type type = access_type::read;
    ju_get_field(jk, "type"s, type, new_path);
    access.set_type(type);
    uint64_t log2_size = 0;
    ju_get_field(jk, "log2_size"s, log2_size, new_path);
    if (log2_size > INT_MAX) {
        throw std::domain_error("field \""s + new_path + "log2_size\" is out of bounds");
    }
    access.set_log2_size(static_cast<int>(log2_size));
    uint64_t address = 0;
    ju_get_field(jk, "address"s, address, new_path);
    access.set_address(address);
    access_data read_data;
    ju_get_field(jk, "read"s, read_data, new_path);
    if (read_data.size() != (UINT64_C(1) << log2_size)) {
        throw std::invalid_argument("field \""s + new_path + "read\" has wrong length");
    }
    access.set_read(std::move(read_data));
    if (type == access_type::write) {
        access_data write_data;
        ju_get_field(jk, "written"s, write_data, new_path);
        if (write_data.size() != (UINT64_C(1) << log2_size)) {
            throw std::invalid_argument("field \""s + new_path + "written\" has wrong length");
        }
        access.set_written(std::move(write_data));
    }
    not_default_constructible<machine_merkle_tree::proof_type> proof;
    ju_get_opt_field(jk, "proof"s, proof, new_path);
    if (proof.has_value()) {
        access.set_proof(std::move(proof).value());
    }
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, access &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, access &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, bracket_type &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    const auto &v = jk.template get<std::string>();
    if (v == "begin") {
        value = bracket_type::begin;
        return;
    }
    if (v == "end") {
        value = bracket_type::end;
        return;
    }
    throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a bracket type");
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, bracket_type &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, bracket_type &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, bracket_note &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_object()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an object");
    }
    const auto new_path = path + to_string(key) + "/";
    ju_get_field(jk, "type"s, value.type, new_path);
    ju_get_field(jk, "where"s, value.where, new_path);
    ju_get_opt_field(jk, "text"s, value.text, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, bracket_note &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, bracket_note &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, not_default_constructible<access_log::type> &optional,
    const std::string &path) {
    optional = {};
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    const auto new_path = path + to_string(key) + "/";
    bool has_proofs = false;
    ju_get_field(jk, "has_proofs"s, has_proofs, new_path);
    bool has_annotations = false;
    ju_get_field(jk, "has_annotations"s, has_annotations, new_path);
    optional.emplace(has_proofs, has_annotations);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key,
    not_default_constructible<access_log::type> &value, const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    not_default_constructible<access_log::type> &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, not_default_constructible<access_log> &optional,
    const std::string &path) {
    optional = {};
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    const auto new_path = path + to_string(key) + "/";
    not_default_constructible<access_log::type> log_type;
    ju_get_field(jk, "log_type"s, log_type, new_path);
    if (!log_type.has_value()) {
        throw std::logic_error("log_type conversion bug");
    }
    std::vector<access> accesses;
    ju_get_vector_like_field(jk, "accesses"s, accesses, new_path);
    if (log_type.value().has_proofs()) {
        for (unsigned i = 0; i < accesses.size(); ++i) {
            if (!accesses[i].get_proof().has_value()) {
                throw std::invalid_argument("field \""s + new_path + "accesses/" + to_string(i) + "\" missing proof");
            }
        }
    }
    std::vector<bracket_note> brackets;
    std::vector<std::string> notes;
    if (log_type.value().has_annotations()) {
        ju_get_vector_like_field(jk, "notes"s, notes, new_path);
        if (notes.size() != accesses.size()) {
            throw std::invalid_argument(
                "size of fields \""s + new_path + "accesses\" and \"" + new_path + "notes\" do not match");
        }
        ju_get_vector_like_field(jk, "brackets"s, brackets, new_path);
        for (unsigned i = 0; i < brackets.size(); ++i) {
            if (brackets[i].where > accesses.size()) {
                throw std::invalid_argument(
                    "field \""s + new_path + "brackets/" + to_string(i) + "/where\" is out of range");
            }
        }
    }
    optional.emplace(std::move(accesses), std::move(brackets), std::move(notes), log_type.value());
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key,
    not_default_constructible<access_log> &value, const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    not_default_constructible<access_log> &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, processor_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_array_like_field(jconfig, "x"s, value.x, new_path);
    ju_get_opt_array_like_field(jconfig, "f"s, value.f, new_path);
    ju_get_opt_field(jconfig, "pc"s, value.pc, new_path);
    ju_get_opt_field(jconfig, "fcsr"s, value.fcsr, new_path);
    ju_get_opt_field(jconfig, "mvendorid"s, value.mvendorid, new_path);
    ju_get_opt_field(jconfig, "marchid"s, value.marchid, new_path);
    ju_get_opt_field(jconfig, "mimpid"s, value.mimpid, new_path);
    ju_get_opt_field(jconfig, "mcycle"s, value.mcycle, new_path);
    ju_get_opt_field(jconfig, "icycleinstret"s, value.icycleinstret, new_path);
    ju_get_opt_field(jconfig, "mstatus"s, value.mstatus, new_path);
    ju_get_opt_field(jconfig, "mtvec"s, value.mtvec, new_path);
    ju_get_opt_field(jconfig, "mscratch"s, value.mscratch, new_path);
    ju_get_opt_field(jconfig, "mepc"s, value.mepc, new_path);
    ju_get_opt_field(jconfig, "mcause"s, value.mcause, new_path);
    ju_get_opt_field(jconfig, "mtval"s, value.mtval, new_path);
    ju_get_opt_field(jconfig, "misa"s, value.misa, new_path);
    ju_get_opt_field(jconfig, "mie"s, value.mie, new_path);
    ju_get_opt_field(jconfig, "mip"s, value.mip, new_path);
    ju_get_opt_field(jconfig, "medeleg"s, value.medeleg, new_path);
    ju_get_opt_field(jconfig, "mideleg"s, value.mideleg, new_path);
    ju_get_opt_field(jconfig, "mcounteren"s, value.mcounteren, new_path);
    ju_get_opt_field(jconfig, "menvcfg"s, value.menvcfg, new_path);
    ju_get_opt_field(jconfig, "stvec"s, value.stvec, new_path);
    ju_get_opt_field(jconfig, "sscratch"s, value.sscratch, new_path);
    ju_get_opt_field(jconfig, "sepc"s, value.sepc, new_path);
    ju_get_opt_field(jconfig, "scause"s, value.scause, new_path);
    ju_get_opt_field(jconfig, "stval"s, value.stval, new_path);
    ju_get_opt_field(jconfig, "satp"s, value.satp, new_path);
    ju_get_opt_field(jconfig, "scounteren"s, value.scounteren, new_path);
    ju_get_opt_field(jconfig, "senvcfg"s, value.senvcfg, new_path);
    ju_get_opt_field(jconfig, "ilrsc"s, value.ilrsc, new_path);
    ju_get_opt_field(jconfig, "iflags"s, value.iflags, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, processor_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, processor_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, rom_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "bootargs"s, value.bootargs, new_path);
    ju_get_opt_field(jconfig, "image_filename"s, value.image_filename, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, rom_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, rom_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, ram_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_field(jconfig, "length"s, value.length, new_path);
    ju_get_opt_field(jconfig, "image_filename"s, value.image_filename, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, ram_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, ram_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, memory_range_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "start"s, value.start, new_path);
    ju_get_opt_field(jconfig, "length"s, value.length, new_path);
    ju_get_opt_field(jconfig, "shared"s, value.shared, new_path);
    ju_get_opt_field(jconfig, "image_filename"s, value.image_filename, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, memory_range_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, memory_range_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, flash_drive_configs &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jflash_drive = j[key];
    if (!jflash_drive.is_array()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an array"s);
    }
    const auto new_path = path + to_string(key) + "/";
    value.resize(0);
    for (uint64_t i = 0; i < jflash_drive.size(); ++i) {
        value.push_back({});
        ju_get_opt_field(jflash_drive, i, value.back(), new_path);
    }
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, flash_drive_configs &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, flash_drive_configs &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, tlb_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "image_filename"s, value.image_filename, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, tlb_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, tlb_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, clint_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "mtimecmp"s, value.mtimecmp, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, clint_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, clint_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, htif_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "fromhost"s, value.fromhost, new_path);
    ju_get_opt_field(jconfig, "tohost"s, value.tohost, new_path);
    ju_get_opt_field(jconfig, "console_getchar"s, value.console_getchar, new_path);
    ju_get_opt_field(jconfig, "yield_manual"s, value.yield_manual, new_path);
    ju_get_opt_field(jconfig, "yield_automatic"s, value.yield_automatic, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, htif_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, htif_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, rollup_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_field(jconfig, "rx_buffer"s, value.rx_buffer, new_path);
    ju_get_field(jconfig, "tx_buffer"s, value.tx_buffer, new_path);
    ju_get_field(jconfig, "input_metadata"s, value.input_metadata, new_path);
    ju_get_field(jconfig, "voucher_hashes"s, value.voucher_hashes, new_path);
    ju_get_field(jconfig, "notice_hashes"s, value.notice_hashes, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, rollup_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, rollup_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, std::optional<rollup_config> &optional,
    const std::string &path) {
    optional.reset();
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    optional.emplace();
    auto &value = optional.value();
    ju_get_field(jconfig, "rx_buffer"s, value.rx_buffer, new_path);
    ju_get_field(jconfig, "tx_buffer"s, value.tx_buffer, new_path);
    ju_get_field(jconfig, "input_metadata"s, value.input_metadata, new_path);
    ju_get_field(jconfig, "voucher_hashes"s, value.voucher_hashes, new_path);
    ju_get_field(jconfig, "notice_hashes"s, value.notice_hashes, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key,
    std::optional<rollup_config> &value, const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    std::optional<rollup_config> &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_processor_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_array_like_field(jconfig, "x"s, value.x, new_path);
    ju_get_opt_field(jconfig, "pc"s, value.pc, new_path);
    ju_get_opt_field(jconfig, "cycle"s, value.cycle, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, uarch_processor_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    uarch_processor_config &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_ram_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "length"s, value.length, new_path);
    ju_get_opt_field(jconfig, "image_filename"s, value.image_filename, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, uarch_ram_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, uarch_ram_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &juarch = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(juarch, "processor"s, value.processor, new_path);
    ju_get_opt_field(juarch, "ram"s, value.ram, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, uarch_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, uarch_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &config = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(config, "processor"s, value.processor, new_path);
    ju_get_opt_field(config, "ram"s, value.ram, new_path);
    ju_get_opt_field(config, "rom"s, value.rom, new_path);
    ju_get_opt_field(config, "flash_drive"s, value.flash_drive, new_path);
    ju_get_opt_field(config, "tlb"s, value.tlb, new_path);
    ju_get_opt_field(config, "clint"s, value.clint, new_path);
    ju_get_opt_field(config, "htif"s, value.htif, new_path);
    ju_get_opt_field(config, "uarch"s, value.uarch, new_path);
    ju_get_opt_field(config, "rollup"s, value.rollup, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, machine_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, machine_config &value,
    const std::string &path);

void to_json(nlohmann::json &j, const machine::csr &csr) {
    j = csr_to_name(csr);
}

void to_json(nlohmann::json &j, const machine_merkle_tree::hash_type &h) {
    j = encode_base64(h);
}

void to_json(nlohmann::json &j, const std::vector<machine_merkle_tree::hash_type> &hs) {
    j = nlohmann::json::array();
    std::transform(hs.cbegin(), hs.cend(), std::back_inserter(j),
        [](const machine_merkle_tree::hash_type &h) -> nlohmann::json { return h; });
}

void to_json(nlohmann::json &j, const machine_merkle_tree::proof_type &p) {
    nlohmann::json s = nlohmann::json::array();
    for (int log2_size = p.get_log2_root_size() - 1; log2_size >= p.get_log2_target_size(); --log2_size) {
        s.push_back(encode_base64(p.get_sibling_hash(log2_size)));
    }
    j = nlohmann::json{{"target_address", p.get_target_address()}, {"log2_target_size", p.get_log2_target_size()},
        {"log2_root_size", p.get_log2_root_size()}, {"target_hash", encode_base64(p.get_target_hash())},
        {"root_hash", encode_base64(p.get_root_hash())}, {"sibling_hashes", s}};
}

void to_json(nlohmann::json &j, const access &a) {
    j = nlohmann::json{
        {"type", access_type_name(a.get_type())},
        {"address", a.get_address()},
        {"log2_size", a.get_log2_size()},
        {"read", encode_base64(a.get_read())},
    };
    if (a.get_type() == access_type::write) {
        j["written"] = encode_base64(a.get_written());
    }
    if (a.get_proof().has_value()) {
        j["proof"] = a.get_proof().value(); // NOLINT(bugprone-unchecked-optional-access)
    }
}

void to_json(nlohmann::json &j, const bracket_note &b) {
    j = nlohmann::json{{"type", bracket_type_name(b.type)}, {"where", b.where}, {"text", b.text}};
}

void to_json(nlohmann::json &j, const std::vector<bracket_note> &bs) {
    j = nlohmann::json::array();
    std::transform(bs.cbegin(), bs.cend(), std::back_inserter(j),
        [](const bracket_note &b) -> nlohmann::json { return b; });
}

void to_json(nlohmann::json &j, const std::vector<access> &as) {
    j = nlohmann::json::array();
    std::transform(as.cbegin(), as.cend(), std::back_inserter(j), [](const access &a) -> nlohmann::json { return a; });
}

void to_json(nlohmann::json &j, const access_log::type &log_type) {
    j = nlohmann::json{
        {"has_proofs", log_type.has_proofs()},
        {"has_annotations", log_type.has_annotations()},
    };
}

void to_json(nlohmann::json &j, const access_log &log) {
    j = nlohmann::json{{"log_type", log.get_log_type()}, {"accesses", log.get_accesses()}};
    if (log.get_log_type().has_annotations()) {
        j["notes"] = log.get_notes();
        j["brackets"] = log.get_brackets();
    }
}

void to_json(nlohmann::json &j, const memory_range_config &config) {
    j = nlohmann::json{{"start", config.start}, {"length", config.length}, {"shared", config.shared},
        {"image_filename", config.image_filename}};
}

void to_json(nlohmann::json &j, const processor_config &config) {
    j = nlohmann::json{{"x", config.x}, {"f", config.f}, {"pc", config.pc}, {"fcsr", config.fcsr},
        {"mvendorid", config.mvendorid}, {"marchid", config.marchid}, {"mimpid", config.mimpid},
        {"mcycle", config.mcycle}, {"icycleinstret", config.icycleinstret}, {"mstatus", config.mstatus},
        {"mtvec", config.mtvec}, {"mscratch", config.mscratch}, {"mepc", config.mepc}, {"mcause", config.mcause},
        {"mtval", config.mtval}, {"misa", config.misa}, {"mie", config.mie}, {"mip", config.mip},
        {"medeleg", config.medeleg}, {"mideleg", config.mideleg}, {"mcounteren", config.mcounteren},
        {"menvcfg", config.menvcfg}, {"stvec", config.stvec}, {"sscratch", config.sscratch}, {"sepc", config.sepc},
        {"scause", config.scause}, {"stval", config.stval}, {"satp", config.satp}, {"scounteren", config.scounteren},
        {"senvcfg", config.senvcfg}, {"ilrsc", config.ilrsc}, {"iflags", config.iflags}};
}

void to_json(nlohmann::json &j, const flash_drive_configs &fs) {
    j = nlohmann::json::array();
    std::transform(fs.cbegin(), fs.cend(), std::back_inserter(j),
        [](const memory_range_config &m) -> nlohmann::json { return m; });
}

void to_json(nlohmann::json &j, const ram_config &config) {
    j = nlohmann::json{
        {"length", config.length},
        {"image_filename", config.image_filename},
    };
}

void to_json(nlohmann::json &j, const rom_config &config) {
    j = nlohmann::json{
        {"bootargs", config.bootargs},
        {"image_filename", config.image_filename},
    };
}

void to_json(nlohmann::json &j, const tlb_config &config) {
    j = nlohmann::json{
        {"image_filename", config.image_filename},
    };
}

void to_json(nlohmann::json &j, const clint_config &config) {
    j = nlohmann::json{
        {"mtimecmp", config.mtimecmp},
    };
}

void to_json(nlohmann::json &j, const htif_config &config) {
    j = nlohmann::json{
        {"fromhost", config.fromhost},
        {"tohost", config.tohost},
        {"console_getchar", config.console_getchar},
        {"yield_manual", config.yield_manual},
        {"yield_automatic", config.yield_automatic},
    };
}

void to_json(nlohmann::json &j, const rollup_config &config) {
    j = nlohmann::json{
        {"rx_buffer", config.rx_buffer},
        {"tx_buffer", config.tx_buffer},
        {"input_metadata", config.input_metadata},
        {"voucher_hashes", config.voucher_hashes},
        {"notice_hashes", config.notice_hashes},
    };
}

void to_json(nlohmann::json &j, const uarch_processor_config &config) {
    j = nlohmann::json{
        {"x", config.x},
        {"pc", config.pc},
        {"cycle", config.cycle},
    };
}

void to_json(nlohmann::json &j, const uarch_ram_config &config) {
    j = nlohmann::json{
        {"length", config.length},
        {"image_filename", config.image_filename},
    };
}

void to_json(nlohmann::json &j, const uarch_config &config) {
    j = nlohmann::json{
        {"processor", config.processor},
        {"ram", config.ram},
    };
}

void to_json(nlohmann::json &j, const machine_config &config) {
    j = nlohmann::json{
        {"processor", config.processor},
        {"ram", config.ram},
        {"rom", config.rom},
        {"flash_drive", config.flash_drive},
        {"tlb", config.tlb},
        {"clint", config.clint},
        {"htif", config.htif},
        {"uarch", config.uarch},
    };
    if (config.rollup.has_value()) {
        j["rollup"] = config.rollup.value();
    }
}

void to_json(nlohmann::json &j, const concurrency_runtime_config &config) {
    j = nlohmann::json{
        {"update_merkle_tree", config.update_merkle_tree},
    };
}

void to_json(nlohmann::json &j, const htif_runtime_config &config) {
    j = nlohmann::json{
        {"no_console_putchar", config.no_console_putchar},
    };
}

void to_json(nlohmann::json &j, const machine_runtime_config &runtime) {
    j = nlohmann::json{
        {"concurrency", runtime.concurrency},
        {"htif", runtime.htif},
        {"skip_root_hash_check", runtime.skip_root_hash_check},
        {"skip_version_check", runtime.skip_version_check},
    };
}

} // namespace cartesi
