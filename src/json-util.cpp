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

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include "json-util.h"
#include "access-log.h"
#include "base64.h"
#include "bracket-note.h"
#include "interpret.h"
#include "jsonrpc-virtual-machine.h"
#include "machine-config.h"
#include "machine-memory-range-descr.h"
#include "machine-merkle-tree.h"
#include "machine-runtime-config.h"
#include "machine.h"
#include "semantic-version.h"
#include "uarch-config.h"
#include "uarch-interpret.h"

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

/// \brief Converts between a register name and a register index
/// \param name Register name
/// \returns The register index
static auto reg_from_name(const std::string &name) {
    using reg = machine::reg;
    const static std::unordered_map<std::string, reg> g_reg_name = {
        {"x0", reg::x0},
        {"x1", reg::x1},
        {"x2", reg::x2},
        {"x3", reg::x3},
        {"x4", reg::x4},
        {"x5", reg::x5},
        {"x6", reg::x6},
        {"x7", reg::x7},
        {"x8", reg::x8},
        {"x9", reg::x9},
        {"x10", reg::x10},
        {"x11", reg::x11},
        {"x12", reg::x12},
        {"x13", reg::x13},
        {"x14", reg::x14},
        {"x15", reg::x15},
        {"x16", reg::x16},
        {"x17", reg::x17},
        {"x18", reg::x18},
        {"x19", reg::x19},
        {"x20", reg::x20},
        {"x21", reg::x21},
        {"x22", reg::x22},
        {"x23", reg::x23},
        {"x24", reg::x24},
        {"x25", reg::x25},
        {"x26", reg::x26},
        {"x27", reg::x27},
        {"x28", reg::x28},
        {"x29", reg::x29},
        {"x30", reg::x30},
        {"x31", reg::x31},
        {"f0", reg::f0},
        {"f1", reg::f1},
        {"f2", reg::f2},
        {"f3", reg::f3},
        {"f4", reg::f4},
        {"f5", reg::f5},
        {"f6", reg::f6},
        {"f7", reg::f7},
        {"f8", reg::f8},
        {"f9", reg::f9},
        {"f10", reg::f10},
        {"f11", reg::f11},
        {"f12", reg::f12},
        {"f13", reg::f13},
        {"f14", reg::f14},
        {"f15", reg::f15},
        {"f16", reg::f16},
        {"f17", reg::f17},
        {"f18", reg::f18},
        {"f19", reg::f19},
        {"f20", reg::f20},
        {"f21", reg::f21},
        {"f22", reg::f22},
        {"f23", reg::f23},
        {"f24", reg::f24},
        {"f25", reg::f25},
        {"f26", reg::f26},
        {"f27", reg::f27},
        {"f28", reg::f28},
        {"f29", reg::f29},
        {"f30", reg::f30},
        {"f31", reg::f31},
        {"pc", reg::pc},
        {"fcsr", reg::fcsr},
        {"mvendorid", reg::mvendorid},
        {"marchid", reg::marchid},
        {"mimpid", reg::mimpid},
        {"mcycle", reg::mcycle},
        {"icycleinstret", reg::icycleinstret},
        {"mstatus", reg::mstatus},
        {"mtvec", reg::mtvec},
        {"mscratch", reg::mscratch},
        {"mepc", reg::mepc},
        {"mcause", reg::mcause},
        {"mtval", reg::mtval},
        {"misa", reg::misa},
        {"mie", reg::mie},
        {"mip", reg::mip},
        {"medeleg", reg::medeleg},
        {"mideleg", reg::mideleg},
        {"mcounteren", reg::mcounteren},
        {"menvcfg", reg::menvcfg},
        {"stvec", reg::stvec},
        {"sscratch", reg::sscratch},
        {"sepc", reg::sepc},
        {"scause", reg::scause},
        {"stval", reg::stval},
        {"satp", reg::satp},
        {"scounteren", reg::scounteren},
        {"senvcfg", reg::senvcfg},
        {"ilrsc", reg::ilrsc},
        {"iflags", reg::iflags},
        {"iflags_prv", reg::iflags_prv},
        {"iflags_x", reg::iflags_x},
        {"iflags_y", reg::iflags_y},
        {"iflags_h", reg::iflags_h},
        {"iunrep", reg::iunrep},
        {"clint_mtimecmp", reg::clint_mtimecmp},
        {"plic_girqpend", reg::plic_girqpend},
        {"plic_girqsrvd", reg::plic_girqsrvd},
        {"htif_tohost", reg::htif_tohost},
        {"htif_tohost_dev", reg::htif_tohost_dev},
        {"htif_tohost_cmd", reg::htif_tohost_cmd},
        {"htif_tohost_reason", reg::htif_tohost_reason},
        {"htif_tohost_data", reg::htif_tohost_data},
        {"htif_fromhost", reg::htif_fromhost},
        {"htif_fromhost_dev", reg::htif_fromhost_dev},
        {"htif_fromhost_cmd", reg::htif_fromhost_cmd},
        {"htif_fromhost_reason", reg::htif_fromhost_reason},
        {"htif_fromhost_data", reg::htif_fromhost_data},
        {"htif_ihalt", reg::htif_ihalt},
        {"htif_iconsole", reg::htif_iconsole},
        {"htif_iyield", reg::htif_iyield},
        {"uarch_x0", reg::uarch_x0},
        {"uarch_x1", reg::uarch_x1},
        {"uarch_x2", reg::uarch_x2},
        {"uarch_x3", reg::uarch_x3},
        {"uarch_x4", reg::uarch_x4},
        {"uarch_x5", reg::uarch_x5},
        {"uarch_x6", reg::uarch_x6},
        {"uarch_x7", reg::uarch_x7},
        {"uarch_x8", reg::uarch_x8},
        {"uarch_x9", reg::uarch_x9},
        {"uarch_x10", reg::uarch_x10},
        {"uarch_x11", reg::uarch_x11},
        {"uarch_x12", reg::uarch_x12},
        {"uarch_x13", reg::uarch_x13},
        {"uarch_x14", reg::uarch_x14},
        {"uarch_x15", reg::uarch_x15},
        {"uarch_x16", reg::uarch_x16},
        {"uarch_x17", reg::uarch_x17},
        {"uarch_x18", reg::uarch_x18},
        {"uarch_x19", reg::uarch_x19},
        {"uarch_x20", reg::uarch_x20},
        {"uarch_x21", reg::uarch_x21},
        {"uarch_x22", reg::uarch_x22},
        {"uarch_x23", reg::uarch_x23},
        {"uarch_x24", reg::uarch_x24},
        {"uarch_x25", reg::uarch_x25},
        {"uarch_x26", reg::uarch_x26},
        {"uarch_x27", reg::uarch_x27},
        {"uarch_x28", reg::uarch_x28},
        {"uarch_x29", reg::uarch_x29},
        {"uarch_x30", reg::uarch_x30},
        {"uarch_x31", reg::uarch_x31},
        {"uarch_pc", reg::uarch_pc},
        {"uarch_cycle", reg::uarch_cycle},
        {"uarch_halt_flag", reg::uarch_halt_flag},
    };
    auto got = g_reg_name.find(name);
    if (got == g_reg_name.end()) {
        throw std::domain_error{"invalid register"};
    }
    return got->second;
}

static auto reg_to_name(machine::reg r) {
    using reg = machine::reg;
    switch (r) {
        case reg::x0:
            return "x0";
        case reg::x1:
            return "x1";
        case reg::x2:
            return "x2";
        case reg::x3:
            return "x3";
        case reg::x4:
            return "x4";
        case reg::x5:
            return "x5";
        case reg::x6:
            return "x6";
        case reg::x7:
            return "x7";
        case reg::x8:
            return "x8";
        case reg::x9:
            return "x9";
        case reg::x10:
            return "x10";
        case reg::x11:
            return "x11";
        case reg::x12:
            return "x12";
        case reg::x13:
            return "x13";
        case reg::x14:
            return "x14";
        case reg::x15:
            return "x15";
        case reg::x16:
            return "x16";
        case reg::x17:
            return "x17";
        case reg::x18:
            return "x18";
        case reg::x19:
            return "x19";
        case reg::x20:
            return "x20";
        case reg::x21:
            return "x21";
        case reg::x22:
            return "x22";
        case reg::x23:
            return "x23";
        case reg::x24:
            return "x24";
        case reg::x25:
            return "x25";
        case reg::x26:
            return "x26";
        case reg::x27:
            return "x27";
        case reg::x28:
            return "x28";
        case reg::x29:
            return "x29";
        case reg::x30:
            return "x30";
        case reg::x31:
            return "x31";
        case reg::f0:
            return "f0";
        case reg::f1:
            return "f1";
        case reg::f2:
            return "f2";
        case reg::f3:
            return "f3";
        case reg::f4:
            return "f4";
        case reg::f5:
            return "f5";
        case reg::f6:
            return "f6";
        case reg::f7:
            return "f7";
        case reg::f8:
            return "f8";
        case reg::f9:
            return "f9";
        case reg::f10:
            return "f10";
        case reg::f11:
            return "f11";
        case reg::f12:
            return "f12";
        case reg::f13:
            return "f13";
        case reg::f14:
            return "f14";
        case reg::f15:
            return "f15";
        case reg::f16:
            return "f16";
        case reg::f17:
            return "f17";
        case reg::f18:
            return "f18";
        case reg::f19:
            return "f19";
        case reg::f20:
            return "f20";
        case reg::f21:
            return "f21";
        case reg::f22:
            return "f22";
        case reg::f23:
            return "f23";
        case reg::f24:
            return "f24";
        case reg::f25:
            return "f25";
        case reg::f26:
            return "f26";
        case reg::f27:
            return "f27";
        case reg::f28:
            return "f28";
        case reg::f29:
            return "f29";
        case reg::f30:
            return "f30";
        case reg::f31:
            return "f31";
        case reg::pc:
            return "pc";
        case reg::fcsr:
            return "fcsr";
        case reg::mvendorid:
            return "mvendorid";
        case reg::marchid:
            return "marchid";
        case reg::mimpid:
            return "mimpid";
        case reg::mcycle:
            return "mcycle";
        case reg::icycleinstret:
            return "icycleinstret";
        case reg::mstatus:
            return "mstatus";
        case reg::mtvec:
            return "mtvec";
        case reg::mscratch:
            return "mscratch";
        case reg::mepc:
            return "mepc";
        case reg::mcause:
            return "mcause";
        case reg::mtval:
            return "mtval";
        case reg::misa:
            return "misa";
        case reg::mie:
            return "mie";
        case reg::mip:
            return "mip";
        case reg::medeleg:
            return "medeleg";
        case reg::mideleg:
            return "mideleg";
        case reg::mcounteren:
            return "mcounteren";
        case reg::menvcfg:
            return "menvcfg";
        case reg::stvec:
            return "stvec";
        case reg::sscratch:
            return "sscratch";
        case reg::sepc:
            return "sepc";
        case reg::scause:
            return "scause";
        case reg::stval:
            return "stval";
        case reg::satp:
            return "satp";
        case reg::scounteren:
            return "scounteren";
        case reg::senvcfg:
            return "senvcfg";
        case reg::ilrsc:
            return "ilrsc";
        case reg::iflags:
            return "iflags";
        case reg::iflags_prv:
            return "iflags_prv";
        case reg::iflags_x:
            return "iflags_x";
        case reg::iflags_y:
            return "iflags_y";
        case reg::iflags_h:
            return "iflags_h";
        case reg::iunrep:
            return "iunrep";
        case reg::clint_mtimecmp:
            return "clint_mtimecmp";
        case reg::plic_girqpend:
            return "plic_girqpend";
        case reg::plic_girqsrvd:
            return "plic_girqsrvd";
        case reg::htif_tohost:
            return "htif_tohost";
        case reg::htif_tohost_dev:
            return "htif_tohost_dev";
        case reg::htif_tohost_cmd:
            return "htif_tohost_cmd";
        case reg::htif_tohost_reason:
            return "htif_tohost_reason";
        case reg::htif_tohost_data:
            return "htif_tohost_data";
        case reg::htif_fromhost:
            return "htif_fromhost";
        case reg::htif_fromhost_dev:
            return "htif_fromhost_dev";
        case reg::htif_fromhost_cmd:
            return "htif_fromhost_cmd";
        case reg::htif_fromhost_reason:
            return "htif_fromhost_reason";
        case reg::htif_fromhost_data:
            return "htif_fromhost_data";
        case reg::htif_ihalt:
            return "htif_ihalt";
        case reg::htif_iconsole:
            return "htif_iconsole";
        case reg::htif_iyield:
            return "htif_iyield";
        case reg::uarch_x0:
            return "uarch_x0";
        case reg::uarch_x1:
            return "uarch_x1";
        case reg::uarch_x2:
            return "uarch_x2";
        case reg::uarch_x3:
            return "uarch_x3";
        case reg::uarch_x4:
            return "uarch_x4";
        case reg::uarch_x5:
            return "uarch_x5";
        case reg::uarch_x6:
            return "uarch_x6";
        case reg::uarch_x7:
            return "uarch_x7";
        case reg::uarch_x8:
            return "uarch_x8";
        case reg::uarch_x9:
            return "uarch_x9";
        case reg::uarch_x10:
            return "uarch_x10";
        case reg::uarch_x11:
            return "uarch_x11";
        case reg::uarch_x12:
            return "uarch_x12";
        case reg::uarch_x13:
            return "uarch_x13";
        case reg::uarch_x14:
            return "uarch_x14";
        case reg::uarch_x15:
            return "uarch_x15";
        case reg::uarch_x16:
            return "uarch_x16";
        case reg::uarch_x17:
            return "uarch_x17";
        case reg::uarch_x18:
            return "uarch_x18";
        case reg::uarch_x19:
            return "uarch_x19";
        case reg::uarch_x20:
            return "uarch_x20";
        case reg::uarch_x21:
            return "uarch_x21";
        case reg::uarch_x22:
            return "uarch_x22";
        case reg::uarch_x23:
            return "uarch_x23";
        case reg::uarch_x24:
            return "uarch_x24";
        case reg::uarch_x25:
            return "uarch_x25";
        case reg::uarch_x26:
            return "uarch_x26";
        case reg::uarch_x27:
            return "uarch_x27";
        case reg::uarch_x28:
            return "uarch_x28";
        case reg::uarch_x29:
            return "uarch_x29";
        case reg::uarch_x30:
            return "uarch_x30";
        case reg::uarch_x31:
            return "uarch_x31";
        case reg::uarch_pc:
            return "uarch_pc";
        case reg::uarch_cycle:
            return "uarch_cycle";
        case reg::uarch_halt_flag:
            return "uarch_halt_flag";
        default:
            throw std::domain_error{"invalid register"};
            break;
    }
    return "";
}

interpreter_break_reason interpreter_break_reason_from_name(const std::string &name) {
    using ibr = interpreter_break_reason;
    const static std::unordered_map<std::string, ibr> g_ibr_name = {{"failed", ibr::failed}, {"halted", ibr::halted},
        {"yielded_manually", ibr::yielded_manually}, {"yielded_automatically", ibr::yielded_automatically},
        {"yielded_softly", ibr::yielded_softly}, {"reached_target_mcycle", ibr::reached_target_mcycle}};
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
    // in case of negative integers, cast them to the unsigned representation
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

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uint16_t &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    uint64_t value64 = 0;
    ju_get_field(j, key, value64, path);
    if (value64 > UINT16_MAX) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" out of range");
    }
    value = static_cast<uint16_t>(value64);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, uint32_t &value,
    const std::string &path);

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, uint16_t &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, uint32_t &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, uint16_t &value,
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
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine::reg &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    value = reg_from_name(jk.template get<std::string>());
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, machine::reg &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, machine::reg &value,
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
    ju_get_opt_field(j[key], "concurrency"s, value.concurrency, path + to_string(key) + "/");
    ju_get_opt_field(j[key], "htif"s, value.htif, path + to_string(key) + "/");
    ju_get_opt_field(j[key], "skip_root_hash_check"s, value.skip_root_hash_check, path + to_string(key) + "/");
    ju_get_opt_field(j[key], "skip_root_hash_store"s, value.skip_root_hash_store, path + to_string(key) + "/");
    ju_get_opt_field(j[key], "skip_version_check"s, value.skip_version_check, path + to_string(key) + "/");
    ju_get_opt_field(j[key], "soft_yield"s, value.soft_yield, path + to_string(key) + "/");
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

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key,
    std::optional<machine_merkle_tree::proof_type::hash_type> &optional, const std::string &path) {
    optional = {};
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    std::string bin = decode_base64(jk.template get<std::string>());
    optional.emplace();
    if (bin.size() != optional.value().size()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a base64-encoded 256-bit hash");
    }
    std::copy(bin.begin(), bin.end(), optional.value().data());
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
    for (int log2_size = proof.get_log2_target_size(), i = 0; log2_size < proof.get_log2_root_size();
         ++log2_size, ++i) {
        machine_merkle_tree::proof_type::hash_type sibling_hash;
        ju_get_field(sh, i, sibling_hash, sibling_hashes_base);
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

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, std::optional<access_data> &optional,
    const std::string &path) {
    optional = {};
    if (!contains(j, key)) {
        return;
    }
    const auto &jk = j[key];
    if (!jk.is_string()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not a string");
    }
    const auto &bin = decode_base64(jk.template get<std::string>());
    optional.emplace();
    std::copy(bin.begin(), bin.end(), std::back_inserter(optional.value()));
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
    if (log2_size >= 64) {
        throw std::domain_error("field \""s + new_path + "log2_size\" is out of bounds");
    }
    access.set_log2_size(static_cast<int>(log2_size));
    // Minimum logged data size is merkle tree word size
    const uint64_t data_log2_size =
        std::max(log2_size, static_cast<uint64_t>(machine_merkle_tree::get_log2_word_size()));
    uint64_t address = 0;
    ju_get_field(jk, "address"s, address, new_path);
    access.set_address(address);
    machine_merkle_tree::proof_type::hash_type read_hash;
    ju_get_field(jk, "read_hash", read_hash, new_path);
    access.set_read_hash(read_hash);

    not_default_constructible<machine_merkle_tree::proof_type::hash_type> written_hash;
    ju_get_opt_field(jk, "written_hash", written_hash, new_path);
    if (written_hash.has_value()) {
        access.set_written_hash(written_hash.value());
    }

    std::optional<access_data> read;
    ju_get_opt_field(jk, "read"s, read, new_path);
    if (read.has_value()) {
        if (read.value().size() != (UINT64_C(1) << data_log2_size)) {
            throw std::invalid_argument("field \""s + new_path + "written\" has wrong length");
        }
        access.set_read(std::move(read.value()));
    }
    if (type == access_type::write) {
        std::optional<access_data> written;
        ju_get_opt_field(jk, "written"s, written, new_path);
        if (written.has_value()) {
            if (written.value().size() != (UINT64_C(1) << data_log2_size)) {
                throw std::invalid_argument("field \""s + new_path + "written\" has wrong length");
            }
            access.set_written(std::move(written.value()));
        }
    }
    if (contains(jk, "sibling_hashes")) {
        access.get_sibling_hashes().emplace();
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        auto &sibling_hashes = access.get_sibling_hashes().value();
        ju_get_vector_like_field(jk, "sibling_hashes"s, sibling_hashes, new_path);
        auto expected_depth = static_cast<size_t>(machine_merkle_tree::get_log2_root_size() - data_log2_size);
        if (sibling_hashes.size() != expected_depth) {
            throw std::invalid_argument("field \""s + new_path + "sibling_hashes\" has wrong length");
        }
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
    bool has_annotations = false;
    ju_get_field(jk, "has_annotations"s, has_annotations, new_path);
    bool has_large_data = false;
    ju_get_field(jk, "has_large_data"s, has_large_data, new_path);
    optional.emplace(has_annotations, has_large_data);
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
    for (unsigned i = 0; i < accesses.size(); ++i) {
        if (!accesses[i].get_sibling_hashes().has_value()) {
            throw std::invalid_argument(
                "field \""s + new_path + "accesses/" + to_string(i) + "\" missing sibling hashes");
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
    ju_get_opt_field(jconfig, "x0"s, value.x[0], new_path);
    ju_get_opt_field(jconfig, "x1"s, value.x[1], new_path);
    ju_get_opt_field(jconfig, "x2"s, value.x[2], new_path);
    ju_get_opt_field(jconfig, "x3"s, value.x[3], new_path);
    ju_get_opt_field(jconfig, "x4"s, value.x[4], new_path);
    ju_get_opt_field(jconfig, "x5"s, value.x[5], new_path);
    ju_get_opt_field(jconfig, "x6"s, value.x[6], new_path);
    ju_get_opt_field(jconfig, "x7"s, value.x[7], new_path);
    ju_get_opt_field(jconfig, "x8"s, value.x[8], new_path);
    ju_get_opt_field(jconfig, "x9"s, value.x[9], new_path);
    ju_get_opt_field(jconfig, "x10"s, value.x[10], new_path);
    ju_get_opt_field(jconfig, "x11"s, value.x[11], new_path);
    ju_get_opt_field(jconfig, "x12"s, value.x[12], new_path);
    ju_get_opt_field(jconfig, "x13"s, value.x[13], new_path);
    ju_get_opt_field(jconfig, "x14"s, value.x[14], new_path);
    ju_get_opt_field(jconfig, "x15"s, value.x[15], new_path);
    ju_get_opt_field(jconfig, "x16"s, value.x[16], new_path);
    ju_get_opt_field(jconfig, "x17"s, value.x[17], new_path);
    ju_get_opt_field(jconfig, "x18"s, value.x[18], new_path);
    ju_get_opt_field(jconfig, "x19"s, value.x[19], new_path);
    ju_get_opt_field(jconfig, "x20"s, value.x[20], new_path);
    ju_get_opt_field(jconfig, "x21"s, value.x[21], new_path);
    ju_get_opt_field(jconfig, "x22"s, value.x[22], new_path);
    ju_get_opt_field(jconfig, "x23"s, value.x[23], new_path);
    ju_get_opt_field(jconfig, "x24"s, value.x[24], new_path);
    ju_get_opt_field(jconfig, "x25"s, value.x[25], new_path);
    ju_get_opt_field(jconfig, "x26"s, value.x[26], new_path);
    ju_get_opt_field(jconfig, "x27"s, value.x[27], new_path);
    ju_get_opt_field(jconfig, "x28"s, value.x[28], new_path);
    ju_get_opt_field(jconfig, "x29"s, value.x[29], new_path);
    ju_get_opt_field(jconfig, "x30"s, value.x[30], new_path);
    ju_get_opt_field(jconfig, "x31"s, value.x[31], new_path);
    ju_get_opt_field(jconfig, "f0"s, value.f[0], new_path);
    ju_get_opt_field(jconfig, "f1"s, value.f[1], new_path);
    ju_get_opt_field(jconfig, "f2"s, value.f[2], new_path);
    ju_get_opt_field(jconfig, "f3"s, value.f[3], new_path);
    ju_get_opt_field(jconfig, "f4"s, value.f[4], new_path);
    ju_get_opt_field(jconfig, "f5"s, value.f[5], new_path);
    ju_get_opt_field(jconfig, "f6"s, value.f[6], new_path);
    ju_get_opt_field(jconfig, "f7"s, value.f[7], new_path);
    ju_get_opt_field(jconfig, "f8"s, value.f[8], new_path);
    ju_get_opt_field(jconfig, "f9"s, value.f[9], new_path);
    ju_get_opt_field(jconfig, "f10"s, value.f[10], new_path);
    ju_get_opt_field(jconfig, "f11"s, value.f[11], new_path);
    ju_get_opt_field(jconfig, "f12"s, value.f[12], new_path);
    ju_get_opt_field(jconfig, "f13"s, value.f[13], new_path);
    ju_get_opt_field(jconfig, "f14"s, value.f[14], new_path);
    ju_get_opt_field(jconfig, "f15"s, value.f[15], new_path);
    ju_get_opt_field(jconfig, "f16"s, value.f[16], new_path);
    ju_get_opt_field(jconfig, "f17"s, value.f[17], new_path);
    ju_get_opt_field(jconfig, "f18"s, value.f[18], new_path);
    ju_get_opt_field(jconfig, "f19"s, value.f[19], new_path);
    ju_get_opt_field(jconfig, "f20"s, value.f[20], new_path);
    ju_get_opt_field(jconfig, "f21"s, value.f[21], new_path);
    ju_get_opt_field(jconfig, "f22"s, value.f[22], new_path);
    ju_get_opt_field(jconfig, "f23"s, value.f[23], new_path);
    ju_get_opt_field(jconfig, "f24"s, value.f[24], new_path);
    ju_get_opt_field(jconfig, "f25"s, value.f[25], new_path);
    ju_get_opt_field(jconfig, "f26"s, value.f[26], new_path);
    ju_get_opt_field(jconfig, "f27"s, value.f[27], new_path);
    ju_get_opt_field(jconfig, "f28"s, value.f[28], new_path);
    ju_get_opt_field(jconfig, "f29"s, value.f[29], new_path);
    ju_get_opt_field(jconfig, "f30"s, value.f[30], new_path);
    ju_get_opt_field(jconfig, "f31"s, value.f[31], new_path);
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
    ju_get_opt_field(jconfig, "iunrep"s, value.iunrep, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, processor_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, processor_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, dtb_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "bootargs"s, value.bootargs, new_path);
    ju_get_opt_field(jconfig, "init"s, value.init, new_path);
    ju_get_opt_field(jconfig, "entrypoint"s, value.entrypoint, new_path);
    ju_get_opt_field(jconfig, "image_filename"s, value.image_filename, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, dtb_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, dtb_config &value,
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
void ju_get_opt_field(const nlohmann::json &j, const K &key, cmio_buffer_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "shared"s, value.shared, new_path);
    ju_get_opt_field(jconfig, "image_filename"s, value.image_filename, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, cmio_buffer_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, cmio_buffer_config &value,
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
void ju_get_opt_field(const nlohmann::json &j, const K &key, virtio_device_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    std::string type;
    ju_get_opt_field(jconfig, "type"s, type, new_path);
    if (type == "console") {
        value.emplace<virtio_console_config>(virtio_console_config{});
    } else if (type == "p9fs") {
        virtio_p9fs_config p9fs_config;
        ju_get_opt_field(jconfig, "tag"s, p9fs_config.tag, new_path);
        ju_get_opt_field(jconfig, "host_directory"s, p9fs_config.host_directory, new_path);
        value.emplace<virtio_p9fs_config>(std::move(p9fs_config));
    } else if (type == "net-user") {
        virtio_net_user_config net_user_config;
        if (jconfig.contains("hostfwd")) {
            const auto &jhostfwds = jconfig["hostfwd"];
            if (!jhostfwds.is_array()) {
                throw std::invalid_argument("field \""s + new_path + "hostfwd\" not an array"s);
            }
            for (const auto &el : jhostfwds.items()) {
                const auto &jhostfwd = el.value();
                const auto hostfwd_path = new_path + "hostfwd/"s + el.key() + "/"s;
                virtio_hostfwd_config hostfwd;
                ju_get_opt_field(jhostfwd, "is_udp"s, hostfwd.is_udp, hostfwd_path);
                ju_get_opt_field(jhostfwd, "host_ip"s, hostfwd.host_ip, hostfwd_path);
                ju_get_opt_field(jhostfwd, "guest_ip"s, hostfwd.guest_ip, hostfwd_path);
                ju_get_opt_field(jhostfwd, "host_port"s, hostfwd.host_port, hostfwd_path);
                ju_get_opt_field(jhostfwd, "guest_port"s, hostfwd.guest_port, hostfwd_path);
                net_user_config.hostfwd.emplace_back(std::move(hostfwd));
            }
        }
        value.emplace<virtio_net_user_config>(std::move(net_user_config));
    } else if (type == "net-tuntap") {
        virtio_net_tuntap_config net_tuntap_config;
        ju_get_opt_field(jconfig, "iface"s, net_tuntap_config.iface, new_path);
        value.emplace<virtio_net_tuntap_config>(std::move(net_tuntap_config));
    } else {
        throw std::domain_error("invalid virtio device type \""s + type + "\""s);
    }
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, virtio_device_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    virtio_device_config &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, virtio_configs &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jvirtio = j[key];
    if (!jvirtio.is_array()) {
        throw std::invalid_argument("field \""s + path + to_string(key) + "\" not an array"s);
    }
    const auto new_path = path + to_string(key) + "/";
    value.resize(0);
    for (uint64_t i = 0; i < jvirtio.size(); ++i) {
        value.push_back({});
        ju_get_opt_field(jvirtio, i, value.back(), new_path);
    }
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, virtio_configs &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, virtio_configs &value,
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
void ju_get_opt_field(const nlohmann::json &j, const K &key, plic_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "girqpend"s, value.girqpend, new_path);
    ju_get_opt_field(jconfig, "girqsrvd"s, value.girqsrvd, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, plic_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, plic_config &value,
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
void ju_get_opt_field(const nlohmann::json &j, const K &key, cmio_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_field(jconfig, "rx_buffer"s, value.rx_buffer, new_path);
    ju_get_field(jconfig, "tx_buffer"s, value.tx_buffer, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, cmio_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, cmio_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, uarch_processor_config &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "x0"s, value.x[0], new_path);
    ju_get_opt_field(jconfig, "x1"s, value.x[1], new_path);
    ju_get_opt_field(jconfig, "x2"s, value.x[2], new_path);
    ju_get_opt_field(jconfig, "x3"s, value.x[3], new_path);
    ju_get_opt_field(jconfig, "x4"s, value.x[4], new_path);
    ju_get_opt_field(jconfig, "x5"s, value.x[5], new_path);
    ju_get_opt_field(jconfig, "x6"s, value.x[6], new_path);
    ju_get_opt_field(jconfig, "x7"s, value.x[7], new_path);
    ju_get_opt_field(jconfig, "x8"s, value.x[8], new_path);
    ju_get_opt_field(jconfig, "x9"s, value.x[9], new_path);
    ju_get_opt_field(jconfig, "x10"s, value.x[10], new_path);
    ju_get_opt_field(jconfig, "x11"s, value.x[11], new_path);
    ju_get_opt_field(jconfig, "x12"s, value.x[12], new_path);
    ju_get_opt_field(jconfig, "x13"s, value.x[13], new_path);
    ju_get_opt_field(jconfig, "x14"s, value.x[14], new_path);
    ju_get_opt_field(jconfig, "x15"s, value.x[15], new_path);
    ju_get_opt_field(jconfig, "x16"s, value.x[16], new_path);
    ju_get_opt_field(jconfig, "x17"s, value.x[17], new_path);
    ju_get_opt_field(jconfig, "x18"s, value.x[18], new_path);
    ju_get_opt_field(jconfig, "x19"s, value.x[19], new_path);
    ju_get_opt_field(jconfig, "x20"s, value.x[20], new_path);
    ju_get_opt_field(jconfig, "x21"s, value.x[21], new_path);
    ju_get_opt_field(jconfig, "x22"s, value.x[22], new_path);
    ju_get_opt_field(jconfig, "x23"s, value.x[23], new_path);
    ju_get_opt_field(jconfig, "x24"s, value.x[24], new_path);
    ju_get_opt_field(jconfig, "x25"s, value.x[25], new_path);
    ju_get_opt_field(jconfig, "x26"s, value.x[26], new_path);
    ju_get_opt_field(jconfig, "x27"s, value.x[27], new_path);
    ju_get_opt_field(jconfig, "x28"s, value.x[28], new_path);
    ju_get_opt_field(jconfig, "x29"s, value.x[29], new_path);
    ju_get_opt_field(jconfig, "x30"s, value.x[30], new_path);
    ju_get_opt_field(jconfig, "x31"s, value.x[31], new_path);
    ju_get_opt_field(jconfig, "pc"s, value.pc, new_path);
    ju_get_opt_field(jconfig, "cycle"s, value.cycle, new_path);
    ju_get_opt_field(jconfig, "halt_flag"s, value.halt_flag, new_path);
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
    ju_get_opt_field(config, "dtb"s, value.dtb, new_path);
    ju_get_opt_field(config, "flash_drive"s, value.flash_drive, new_path);
    ju_get_opt_field(config, "virtio"s, value.virtio, new_path);
    ju_get_opt_field(config, "tlb"s, value.tlb, new_path);
    ju_get_opt_field(config, "clint"s, value.clint, new_path);
    ju_get_opt_field(config, "plic"s, value.plic, new_path);
    ju_get_opt_field(config, "htif"s, value.htif, new_path);
    ju_get_opt_field(config, "uarch"s, value.uarch, new_path);
    ju_get_opt_field(config, "cmio"s, value.cmio, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, machine_config &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, machine_config &value,
    const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_memory_range_descr &value,
    const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "length"s, value.length, new_path);
    ju_get_opt_field(jconfig, "start"s, value.start, new_path);
    ju_get_opt_field(jconfig, "description"s, value.description, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key,
    machine_memory_range_descr &value, const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    machine_memory_range_descr &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, machine_memory_range_descrs &value,
    const std::string &path) {
    ju_get_opt_vector_like_field(j, key, value, path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key,
    machine_memory_range_descrs &value, const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key,
    machine_memory_range_descrs &value, const std::string &path);

template <typename K>
void ju_get_opt_field(const nlohmann::json &j, const K &key, fork_result &value, const std::string &path) {
    if (!contains(j, key)) {
        return;
    }
    const auto &jconfig = j[key];
    const auto new_path = path + to_string(key) + "/";
    ju_get_opt_field(jconfig, "address"s, value.address, new_path);
    ju_get_opt_field(jconfig, "pid"s, value.pid, new_path);
}

template void ju_get_opt_field<uint64_t>(const nlohmann::json &j, const uint64_t &key, fork_result &value,
    const std::string &path);

template void ju_get_opt_field<std::string>(const nlohmann::json &j, const std::string &key, fork_result &value,
    const std::string &path);

void to_json(nlohmann::json &j, const machine::reg &reg) {
    j = reg_to_name(reg);
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
    for (int log2_size = p.get_log2_target_size(); log2_size < p.get_log2_root_size(); ++log2_size) {
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
    };

    j["read_hash"] = encode_base64(a.get_read_hash());
    if (a.get_read().has_value()) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        j["read"] = encode_base64(a.get_read().value());
    }

    if (a.get_type() == access_type::write) {
        if (a.get_written_hash().has_value()) {
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            j["written_hash"] = encode_base64(a.get_written_hash().value());
        }
        if (a.get_written().has_value()) {
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            j["written"] = encode_base64(a.get_written().value());
        }
    }
    if (a.get_sibling_hashes().has_value()) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        const auto &sibling_hashes = a.get_sibling_hashes().value();
        // Minimum logged data size is merkle tree word size
        auto data_log2_size = std::max(a.get_log2_size(), machine_merkle_tree::get_log2_word_size());
        auto depth = machine_merkle_tree::get_log2_root_size() - data_log2_size;
        nlohmann::json s = nlohmann::json::array();
        for (int i = 0; i < depth; i++) {
            s.push_back(encode_base64(sibling_hashes[i]));
        }
        j["sibling_hashes"] = s;
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
    j = nlohmann::json{{"has_annotations", log_type.has_annotations()}, {"has_large_data", log_type.has_large_data()}};
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

void to_json(nlohmann::json &j, const cmio_buffer_config &config) {
    j = nlohmann::json{{"shared", config.shared}, {"image_filename", config.image_filename}};
}

void to_json(nlohmann::json &j, const processor_config &config) {
    j = nlohmann::json{{"x0", config.x[0]}, {"x1", config.x[1]}, {"x2", config.x[2]}, {"x3", config.x[3]},
        {"x4", config.x[4]}, {"x5", config.x[5]}, {"x6", config.x[6]}, {"x7", config.x[7]}, {"x8", config.x[8]},
        {"x9", config.x[9]}, {"x10", config.x[10]}, {"x11", config.x[11]}, {"x12", config.x[12]}, {"x13", config.x[13]},
        {"x14", config.x[14]}, {"x15", config.x[15]}, {"x16", config.x[16]}, {"x17", config.x[17]},
        {"x18", config.x[18]}, {"x19", config.x[19]}, {"x20", config.x[20]}, {"x21", config.x[21]},
        {"x22", config.x[22]}, {"x23", config.x[23]}, {"x24", config.x[24]}, {"x25", config.x[25]},
        {"x26", config.x[26]}, {"x27", config.x[27]}, {"x28", config.x[28]}, {"x29", config.x[29]},
        {"x30", config.x[30]}, {"x31", config.x[31]}, {"f0", config.f[0]}, {"f1", config.f[1]}, {"f2", config.f[2]},
        {"f3", config.f[3]}, {"f4", config.f[4]}, {"f5", config.f[5]}, {"f6", config.f[6]}, {"f7", config.f[7]},
        {"f8", config.f[8]}, {"f9", config.f[9]}, {"f10", config.f[10]}, {"f11", config.f[11]}, {"f12", config.f[12]},
        {"f13", config.f[13]}, {"f14", config.f[14]}, {"f15", config.f[15]}, {"f16", config.f[16]},
        {"f17", config.f[17]}, {"f18", config.f[18]}, {"f19", config.f[19]}, {"f20", config.f[20]},
        {"f21", config.f[21]}, {"f22", config.f[22]}, {"f23", config.f[23]}, {"f24", config.f[24]},
        {"f25", config.f[25]}, {"f26", config.f[26]}, {"f27", config.f[27]}, {"f28", config.f[28]},
        {"f29", config.f[29]}, {"f30", config.f[30]}, {"f31", config.f[31]}, {"pc", config.pc}, {"fcsr", config.fcsr},
        {"mvendorid", config.mvendorid}, {"marchid", config.marchid}, {"mimpid", config.mimpid},
        {"mcycle", config.mcycle}, {"icycleinstret", config.icycleinstret}, {"mstatus", config.mstatus},
        {"mtvec", config.mtvec}, {"mscratch", config.mscratch}, {"mepc", config.mepc}, {"mcause", config.mcause},
        {"mtval", config.mtval}, {"misa", config.misa}, {"mie", config.mie}, {"mip", config.mip},
        {"medeleg", config.medeleg}, {"mideleg", config.mideleg}, {"mcounteren", config.mcounteren},
        {"menvcfg", config.menvcfg}, {"stvec", config.stvec}, {"sscratch", config.sscratch}, {"sepc", config.sepc},
        {"scause", config.scause}, {"stval", config.stval}, {"satp", config.satp}, {"scounteren", config.scounteren},
        {"senvcfg", config.senvcfg}, {"ilrsc", config.ilrsc}, {"iflags", config.iflags}, {"iunrep", config.iunrep}};
}

void to_json(nlohmann::json &j, const flash_drive_configs &fs) {
    j = nlohmann::json::array();
    std::transform(fs.cbegin(), fs.cend(), std::back_inserter(j),
        [](const memory_range_config &m) -> nlohmann::json { return m; });
}

void to_json(nlohmann::json &j, const virtio_device_config &config) {
    std::visit(
        [&](const auto &vdev_config) {
            using T = std::decay_t<decltype(vdev_config)>;
            if constexpr (std::is_same_v<T, cartesi::virtio_console_config>) {
                j = nlohmann::json{{"type", "console"}};
            } else if constexpr (std::is_same_v<T, cartesi::virtio_p9fs_config>) {
                j = nlohmann::json{{"type", "p9fs"}, {"tag", vdev_config.tag},
                    {"host_directory", vdev_config.host_directory}};
            } else if constexpr (std::is_same_v<T, cartesi::virtio_net_user_config>) {
                nlohmann::json jhostfwd = nlohmann::json::array();
                std::transform(vdev_config.hostfwd.cbegin(), vdev_config.hostfwd.cend(), std::back_inserter(jhostfwd),
                    [](const virtio_hostfwd_config &h) -> nlohmann::json {
                        return nlohmann::json{
                            {"is_udp", h.is_udp},
                            {"host_ip", h.host_ip},
                            {"guest_ip", h.guest_ip},
                            {"host_port", h.host_port},
                            {"guest_port", h.guest_port},
                        };
                    });
                j = nlohmann::json{{"type", "net-user"}, {"hostfwd", std::move(jhostfwd)}};
            } else if constexpr (std::is_same_v<T, cartesi::virtio_net_tuntap_config>) {
                j = nlohmann::json{{"type", "net-tuntap"}, {"iface", vdev_config.iface}};
            } else {
                throw std::domain_error("invalid virtio device configuration");
            }
        },
        config);
}

void to_json(nlohmann::json &j, const virtio_configs &vs) {
    j = nlohmann::json::array();
    std::transform(vs.cbegin(), vs.cend(), std::back_inserter(j),
        [](const virtio_device_config &v) -> nlohmann::json { return v; });
}

void to_json(nlohmann::json &j, const ram_config &config) {
    j = nlohmann::json{
        {"length", config.length},
        {"image_filename", config.image_filename},
    };
}

void to_json(nlohmann::json &j, const dtb_config &config) {
    j = nlohmann::json{
        {"bootargs", config.bootargs},
        {"init", config.init},
        {"entrypoint", config.entrypoint},
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

void to_json(nlohmann::json &j, const plic_config &config) {
    j = nlohmann::json{
        {"girqpend", config.girqpend},
        {"girqsrvd", config.girqsrvd},
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

void to_json(nlohmann::json &j, const cmio_config &config) {
    j = nlohmann::json{
        {"rx_buffer", config.rx_buffer},
        {"tx_buffer", config.tx_buffer},
    };
}

void to_json(nlohmann::json &j, const uarch_processor_config &config) {
    j = nlohmann::json{
        {"x0", config.x[0]},
        {"x1", config.x[1]},
        {"x2", config.x[2]},
        {"x3", config.x[3]},
        {"x4", config.x[4]},
        {"x5", config.x[5]},
        {"x6", config.x[6]},
        {"x7", config.x[7]},
        {"x8", config.x[8]},
        {"x9", config.x[9]},
        {"x10", config.x[10]},
        {"x11", config.x[11]},
        {"x12", config.x[12]},
        {"x13", config.x[13]},
        {"x14", config.x[14]},
        {"x15", config.x[15]},
        {"x16", config.x[16]},
        {"x17", config.x[17]},
        {"x18", config.x[18]},
        {"x19", config.x[19]},
        {"x20", config.x[20]},
        {"x21", config.x[21]},
        {"x22", config.x[22]},
        {"x23", config.x[23]},
        {"x24", config.x[24]},
        {"x25", config.x[25]},
        {"x26", config.x[26]},
        {"x27", config.x[27]},
        {"x28", config.x[28]},
        {"x29", config.x[29]},
        {"x30", config.x[30]},
        {"x31", config.x[31]},
        {"pc", config.pc},
        {"cycle", config.cycle},
        {"halt_flag", config.halt_flag},
    };
}

void to_json(nlohmann::json &j, const uarch_ram_config &config) {
    j = nlohmann::json{
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
        {"dtb", config.dtb},
        {"flash_drive", config.flash_drive},
        {"virtio", config.virtio},
        {"tlb", config.tlb},
        {"clint", config.clint},
        {"plic", config.plic},
        {"htif", config.htif},
        {"uarch", config.uarch},
        {"cmio", config.cmio},
    };
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
        {"skip_root_hash_store", runtime.skip_root_hash_store},
        {"skip_version_check", runtime.skip_version_check},
        {"soft_yield", runtime.soft_yield},
    };
}

void to_json(nlohmann::json &j, const machine_memory_range_descr &mrd) {
    j = nlohmann::json{{"length", mrd.length}, {"start", mrd.start}, {"description", mrd.description}};
}

void to_json(nlohmann::json &j, const machine_memory_range_descrs &mrds) {
    j = nlohmann::json::array();
    std::transform(mrds.cbegin(), mrds.cend(), std::back_inserter(j),
        [](const auto &a) -> nlohmann::json { return a; });
}

void to_json(nlohmann::json &j, const fork_result &fork_result) {
    j = nlohmann::json{{"address", fork_result.address}, {"pid", fork_result.pid}};
}

void to_json(nlohmann::json &j, const semantic_version &version) {
    j = nlohmann::json{
        {"major", version.major},
        {"minor", version.minor},
        {"patch", version.patch},
        {"pre_release", version.pre_release},
        {"build", version.build},
    };
}

} // namespace cartesi
