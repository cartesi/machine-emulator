// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <boost/endian/conversion.hpp>

#include "machine-config.h"
#include "pma-constants.h"
#include "protobuf-util.h"

static constexpr uint32_t archive_version = 4;

namespace cartesi {

std::string machine_config::get_image_filename(const std::string &dir, uint64_t start, uint64_t length) {
    std::ostringstream sout;
    sout << dir << "/" << std::hex << std::setw(16) << std::setfill('0') << start << "-" << length << ".bin";
    return sout.str();
}

std::string machine_config::get_image_filename(const std::string &dir, const memory_range_config &c) {
    return get_image_filename(dir, c.start, c.length);
}

std::string machine_config::get_config_filename(const std::string &dir) {
    return dir + "/config.protobuf";
}

static void adjust_image_filenames(machine_config &c, const std::string &dir) {
    c.rom.image_filename = c.get_image_filename(dir, PMA_ROM_START, PMA_ROM_LENGTH);
    c.ram.image_filename = c.get_image_filename(dir, PMA_RAM_START, c.ram.length);
    c.tlb.image_filename = c.get_image_filename(dir, PMA_SHADOW_TLB_START, PMA_SHADOW_TLB_LENGTH);
    for (auto &f : c.flash_drive) {
        f.image_filename = c.get_image_filename(dir, f);
    }
    if (c.rollup.has_value()) {
        auto &r = c.rollup.value();
        r.rx_buffer.image_filename = c.get_image_filename(dir, r.rx_buffer);
        r.tx_buffer.image_filename = c.get_image_filename(dir, r.tx_buffer);
        r.input_metadata.image_filename = c.get_image_filename(dir, r.input_metadata);
        r.voucher_hashes.image_filename = c.get_image_filename(dir, r.voucher_hashes);
        r.notice_hashes.image_filename = c.get_image_filename(dir, r.notice_hashes);
    }

    if (c.uarch.ram.length > 0) {
        c.uarch.ram.image_filename = c.get_image_filename(dir, PMA_UARCH_RAM_START, c.uarch.ram.length);
    }
}

machine_config machine_config::load(const std::string &dir) {
    machine_config c;
    auto name = machine_config::get_config_filename(dir);
    std::ifstream ifs(name, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error{"unable to open '" + name + "' for reading"};
    }
    try {
        uint32_t version = 0;
        ifs >> version;
        version = boost::endian::little_to_native(version);
        if (version != archive_version) {
            throw std::runtime_error("expected config archive_version " + std::to_string(archive_version) + " (got " +
                std::to_string(version) + ")");
        }
        CartesiMachine::MachineConfig proto;
        proto.ParseFromIstream(&ifs);
        c = get_proto_machine_config(proto);
        adjust_image_filenames(c, dir);
    } catch (std::exception &e) {
        throw std::runtime_error{e.what()};
    }
    return c;
}

void machine_config::store(const std::string &dir) const {
    auto name = get_config_filename(dir);
    CartesiMachine::MachineConfig proto;
    set_proto_machine_config(*this, &proto);
    std::ofstream ofs(name, std::ios::binary);
    if (!ofs) {
        throw std::runtime_error{"unable to open '" + name + "' for writing"};
    }
    ofs << boost::endian::native_to_little(archive_version);
    proto.SerializeToOstream(&ofs);
}

} // namespace cartesi
