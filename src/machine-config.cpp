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
#include <iomanip>
#include <ios>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>

#include <json.hpp>

#include "address-range-constants.h"
#include "json-util.h"
#include "os-filesystem.h"

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

std::string machine_config::get_dpt_filename(const std::string &dir, uint64_t start, uint64_t length) {
    std::ostringstream sout;
    // dense hash tree
    sout << dir << "/" << std::hex << std::setw(16) << std::setfill('0') << start << "-" << length << ".dpt";
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
    sharing_mode sharing, backing_store_config &c) {
    // Convert sharing mode
    switch (sharing) {
        case sharing_mode::none:
            c.shared = false;
            break;
        case sharing_mode::config:
            // Preserve the shared setting as specified in the configuration
            break;
        case sharing_mode::all:
            c.shared = true;
            break;
    }

    // Strip create and truncate since backing store should be already created
    c.create = false;
    c.truncate = false;

    // Adjust filenames
    c.data_filename = machine_config::get_data_filename(dir, start, length);
    c.dht_filename = machine_config::get_dht_filename(dir, start, length);
    c.dpt_filename = machine_config::get_dpt_filename(dir, start, length);
}

void machine_config::adjust_hash_tree_config(const std::string &dir, hash_tree_config &c) {
    c.sht_filename = machine_config::get_sht_filename(dir);
    c.phtc_filename = machine_config::get_phtc_filename(dir);
}

machine_config &machine_config::adjust_backing_stores(const std::string &dir, sharing_mode sharing) {
    adjust_backing_store_config(AR_RAM_START, ram.length, dir, sharing, ram.backing_store);
    adjust_backing_store_config(AR_DTB_START, AR_DTB_LENGTH, dir, sharing, dtb.backing_store);
    for (auto &f : flash_drive) {
        adjust_backing_store_config(f.start, f.length, dir, sharing, f.backing_store);
    }
    adjust_backing_store_config(AR_SHADOW_STATE_START, AR_SHADOW_STATE_LENGTH, dir, sharing, processor.backing_store);
    adjust_backing_store_config(AR_CMIO_RX_BUFFER_START, AR_CMIO_RX_BUFFER_LENGTH, dir, sharing,
        cmio.rx_buffer.backing_store);
    adjust_backing_store_config(AR_CMIO_TX_BUFFER_START, AR_CMIO_TX_BUFFER_LENGTH, dir, sharing,
        cmio.tx_buffer.backing_store);
    adjust_backing_store_config(AR_PMAS_START, AR_PMAS_LENGTH, dir, sharing, pmas.backing_store);
    adjust_backing_store_config(AR_SHADOW_UARCH_STATE_START, AR_SHADOW_UARCH_STATE_LENGTH, dir, sharing,
        uarch.processor.backing_store);
    adjust_backing_store_config(AR_UARCH_RAM_START, AR_UARCH_RAM_LENGTH, dir, sharing, uarch.ram.backing_store);
    adjust_hash_tree_config(dir, hash_tree);
    return *this;
}

machine_config machine_config::load(const std::string &dir, sharing_mode sharing) {
    if (dir.empty()) {
        throw std::invalid_argument{"directory name cannot be empty"};
    }
    machine_config c;
    auto name = machine_config::get_config_filename(dir);
    const auto [ptr, data] = os::read_file(name);
    try {
        auto j = nlohmann::json::parse(data);
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
        c.adjust_backing_stores(dir, sharing);
    } catch (const std::exception &e) {
        throw std::runtime_error{e.what()};
    }
    return c;
}

std::string machine_config::store(const std::string &dir, sharing_mode sharing) const {
    if (dir.empty()) {
        throw std::invalid_argument{"directory name cannot be empty"};
    }
    auto name = get_config_filename(dir);
    nlohmann::json j;
    j["archive_version"] = archive_version;
    j["config"] = machine_config(*this).adjust_backing_stores(".", sharing); // Strip relative directories
    const std::string data = j.dump();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    os::create_file(name, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(data.data()), data.size()));
    return name;
}

machine_config &machine_config::adjust_defaults() {
    // Fill version registers
    if (processor.registers.marchid == UINT64_C(-1)) {
        processor.registers.marchid = MARCHID_INIT;
    }
    if (processor.registers.mvendorid == UINT64_C(-1)) {
        processor.registers.mvendorid = MVENDORID_INIT;
    }
    if (processor.registers.mimpid == UINT64_C(-1)) {
        processor.registers.mimpid = MIMPID_INIT;
    }
    // Auto detect flash drives start address and length
    int i = 0; // NOLINT(misc-const-correctness)
    for (auto &f : flash_drive) {
        const std::string flash_description = "flash drive "s + std::to_string(i);
        // Auto detect flash drive start address
        if (f.start == UINT64_C(-1)) {
            f.start = AR_DRIVE_START + AR_DRIVE_OFFSET * i;
        }
        // Auto detect flash drive image length
        if (f.length == UINT64_C(-1)) {
            if (f.backing_store.data_filename.empty()) {
                throw std::runtime_error{
                    "unable to auto-detect length of "s.append(flash_description).append(" with empty image file")};
            }
            f.length = os::file_size(f.backing_store.data_filename);
        }
        i += 1;
    }
    return *this;
}

} // namespace cartesi
