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

#include "machine-config.h"

#include <cerrno>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iomanip>
#include <ios>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>

#include <json.hpp>

#include "address-range-constants.h"
#include "json-util.h"

static constexpr uint32_t archive_version = 6;

namespace cartesi {

std::string machine_config::get_data_filename(const std::string &dir, uint64_t start, uint64_t length) {
    std::ostringstream sout;
    sout << dir << "/" << std::hex << std::setw(16) << std::setfill('0') << start << "-" << length << ".bin";
    return sout.str();
}

std::string machine_config::get_dht_filename(const std::string &dir, uint64_t start, uint64_t length) {
    std::ostringstream sout;
    // dense hash tree
    sout << dir << "/" << std::hex << std::setw(16) << std::setfill('0') << start << "-" << length << ".dht";
    return sout.str();
}

std::string machine_config::get_sht_filename(const std::string &dir) {
    // sparse hash tree
    return dir + "/global.sht";
}

std::string machine_config::get_phtc_filename(const std::string &dir) {
    // sparse hash tree
    return dir + "/global.phc";
}

std::string machine_config::get_config_filename(const std::string &dir) {
    return dir + "/config.json";
}

void machine_config::adjust_backing_store_config(uint64_t start, uint64_t length, const std::string &dir,
    backing_store_config &c) {
    c.shared = false;
    c.create = false;
    c.truncate = false;
    c.data_filename = machine_config::get_data_filename(dir, start, length);
    c.dht_filename = machine_config::get_dht_filename(dir, start, length);
}

void machine_config::adjust_hash_tree_config(const std::string &dir, hash_tree_config &c) {
    c.sht_filename = machine_config::get_sht_filename(dir);
    c.phtc_filename = machine_config::get_phtc_filename(dir);
}

void machine_config::adjust_backing_stores(const std::string &dir) {
    adjust_backing_store_config(AR_RAM_START, ram.length, dir, ram.backing_store);
    adjust_backing_store_config(AR_DTB_START, AR_DTB_LENGTH, dir, dtb.backing_store);
    for (auto &f : flash_drive) {
        adjust_backing_store_config(f.start, f.length, dir, f.backing_store);
    }
    adjust_backing_store_config(AR_SHADOW_STATE_START, AR_SHADOW_STATE_LENGTH, dir, processor.backing_store);
    adjust_backing_store_config(AR_CMIO_RX_BUFFER_START, AR_CMIO_RX_BUFFER_LENGTH, dir, cmio.rx_buffer.backing_store);
    adjust_backing_store_config(AR_CMIO_TX_BUFFER_START, AR_CMIO_TX_BUFFER_LENGTH, dir, cmio.tx_buffer.backing_store);
    adjust_backing_store_config(AR_PMAS_START, AR_PMAS_LENGTH, dir, pmas.backing_store);
    adjust_backing_store_config(AR_SHADOW_UARCH_STATE_START, AR_SHADOW_UARCH_STATE_LENGTH, dir,
        uarch.processor.backing_store);
    adjust_backing_store_config(AR_UARCH_RAM_START, AR_UARCH_RAM_LENGTH, dir, uarch.ram.backing_store);
    adjust_hash_tree_config(dir, hash_tree);
}

machine_config machine_config::load(const std::string &dir) {
    machine_config c;
    auto name = machine_config::get_config_filename(dir);
    std::ifstream ifs(name, std::ios::binary);
    if (!ifs) {
        throw std::system_error{errno, std::generic_category(), "unable to open '" + name + "' for reading"};
    }
    try {
        auto j = nlohmann::json::parse(ifs);
        if (!j.contains("archive_version")) {
            throw std::runtime_error("missing field \"archive_version\"");
        }
        auto jv = j["archive_version"];
        if (!jv.is_number_integer()) {
            throw std::runtime_error("expected integer field \"archive_version\"");
        }
        if (jv.get<int>() != archive_version) {
            throw std::runtime_error("expected \"archive_version\" " + std::to_string(archive_version) + " (got " +
                std::to_string(jv.get<int>()) + ")");
        }
        ju_get_field(j, std::string("config"), c, "");
        c.adjust_backing_stores(dir);
    } catch (std::exception &e) {
        throw std::runtime_error{e.what()};
    }
    return c;
}

void machine_config::store(const std::string &dir) const {
    auto name = get_config_filename(dir);
    nlohmann::json j;
    j["archive_version"] = archive_version;
    j["config"] = *this;
    std::ofstream ofs(name, std::ios::binary);
    if (!ofs) {
        throw std::system_error{errno, std::generic_category(), "unable to open '" + name + "' for writing"};
    }
    ofs << j;
}

} // namespace cartesi
