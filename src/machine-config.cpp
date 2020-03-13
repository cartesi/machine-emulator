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

#include <sstream>
#include <iomanip>
#include <fstream>
#include <iostream>

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

#include <boost/serialization/nvp.hpp>
#include <boost/serialization/version.hpp>
#include <boost/serialization/collections_save_imp.hpp>
#include <boost/serialization/collections_load_imp.hpp>

#include "machine-config.h"
#include "pma-constants.h"


namespace boost {
namespace serialization {

template <typename ARX>
inline void save(ARX &ar, const cartesi::flash_configs &t, const unsigned int) {
    boost::serialization::stl::save_collection<ARX, cartesi::flash_configs> (ar, t);
}

template <typename ARX>
inline void load(ARX &ar, cartesi::flash_configs &t, const unsigned int) {
    boost::serialization::collection_size_type count;
    ar >> BOOST_SERIALIZATION_NVP(count);
	if (count > t.capacity()) {
		boost::serialization::throw_exception(
			boost::archive::archive_exception(
				boost::archive::archive_exception::array_size_too_short
			)
		);
	}
    boost::serialization::item_version_type item_version(0);
	auto library_version = ar.get_library_version();
    if(library_version > boost::archive::library_version_type(3)) {
        ar >> BOOST_SERIALIZATION_NVP(item_version);
    }
    boost::serialization::stl::collection_load_impl(ar, t, count, item_version);
}

template <typename ARX>
inline void serialize(ARX &ar, cartesi::flash_configs &t,
    const unsigned int file_version) {
    boost::serialization::split_free(ar, t, file_version);
}

template <typename ARX>
void serialize(ARX &ar, cartesi::processor_config &p, const unsigned int) {
    ar & p.x;
    ar & p.pc;
    ar & p.mvendorid;
    ar & p.marchid;
    ar & p.mimpid;
    ar & p.mcycle;
    ar & p.minstret;
    ar & p.mstatus;
    ar & p.mtvec;
    ar & p.mscratch;
    ar & p.mepc;
    ar & p.mcause;
    ar & p.mtval;
    ar & p.misa;
    ar & p.mie;
    ar & p.mip;
    ar & p.medeleg;
    ar & p.mideleg;
    ar & p.mcounteren;
    ar & p.stvec;
    ar & p.sscratch;
    ar & p.sepc;
    ar & p.scause;
    ar & p.stval;
    ar & p.satp;
    ar & p.scounteren;
    ar & p.ilrsc;
    ar & p.iflags;
}

template <typename ARX>
void serialize(ARX &ar, cartesi::ram_config &r, const unsigned int) {
    ar & r.length;
    ar & r.backing;
}

template <typename ARX>
void serialize(ARX &ar, cartesi::rom_config &r, const unsigned int) {
    ar & r.bootargs;
    ar & r.backing;
}

template <typename ARX>
void serialize(ARX &ar, cartesi::flash_config &d, const unsigned int) {
    ar & d.start;
    ar & d.length;
    ar & d.shared;
    ar & d.backing;
}

template <typename ARX>
void serialize(ARX &ar, cartesi::clint_config &c, const unsigned int) {
    ar & c.mtimecmp;
}

template <typename ARX>
void serialize(ARX &ar, cartesi::htif_config &h, const unsigned int) {
    ar & h.fromhost;
    ar & h.tohost;
    ar & h.interact;
    ar & h.yield;
}


template <typename ARX>
void serialize(ARX &ar, cartesi::machine_config &m, const unsigned int) {
    ar & m.processor;
    ar & m.ram;
    ar & m.rom;
    ar & m.flash;
    ar & m.clint;
    ar & m.htif;
}

} } // namespace boost::serialization

namespace cartesi {

std::string machine_config::get_backing_name(const std::string &dir,
    uint64_t start, uint64_t length) {
    std::ostringstream sout;
    sout << dir << "/" << std::hex << std::setw(16) << std::setfill('0')
        << start << "-" << length << ".bin";
    return sout.str();
}

std::string machine_config::get_config_name(const std::string &dir) {
    return dir + "/config";
}

static void adjust_backing_names(machine_config &c, const std::string &dir) {
    c.rom.backing = c.get_backing_name(dir, PMA_ROM_START, PMA_ROM_LENGTH);
    c.ram.backing = c.get_backing_name(dir, PMA_RAM_START, c.ram.length);
    for (auto &f: c.flash) {
        f.backing = c.get_backing_name(dir, f.start, f.length);
    }
}

machine_config machine_config::load(const std::string &dir) {
    machine_config c;
    auto name = machine_config::get_config_name(dir);
    std::ifstream ifs(name, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error{"unable to open '" + name + "' for reading"};
    }
    boost::archive::binary_iarchive ia(ifs);
    ia >> c;
    adjust_backing_names(c, dir);
    return c;
}

void machine_config::store(const std::string &dir) const {
    auto name = get_config_name(dir);
    std::ofstream ofs(name, std::ios::binary);
    if (!ofs) {
        throw std::runtime_error{"unable to open '" + name + "' for writing"};
    }
    boost::archive::binary_oarchive oa(ofs);
    oa << *this;
}

} // namespace cartesi
