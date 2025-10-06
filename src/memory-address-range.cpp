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

#include "memory-address-range.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <stdexcept>

#include "address-range-constants.h"
#include "address-range.h"
#include "machine-config.h"
#include "os-mapped-memory.h"
#include "pmas.h"

namespace cartesi {

using namespace std::string_literals;

static os::mapped_memory_flags check_mmap_flags(const pmas_flags &flags, const backing_store_config &backing_store,
    const memory_address_range_config &memory_config) {
    if (!flags.M) {
        throw std::invalid_argument{"memory address range must be flagged memory"};
    }
    if (backing_store.shared && backing_store.data_filename.empty()) {
        throw std::invalid_argument{"shared backing store must have a filename"};
    }
    if (backing_store.create && !backing_store.shared) {
        throw std::invalid_argument{"created backing store must also be shared"};
    }
    if (backing_store.truncate && !backing_store.shared) {
        throw std::invalid_argument{"truncated backing store must also be shared"};
    }
    if (memory_config.host_read_only && flags.W) {
        throw std::invalid_argument{"backing store for writable memory address range cannot be read-only"};
    }
    return os::mapped_memory_flags{
        .read_only = memory_config.host_read_only && !backing_store.newly_created(),
        .shared = backing_store.shared,
        .backing_gap = !backing_store.shared,
        .no_reserve = memory_config.host_no_reserve,
    };
}

static const auto throw_invalid_argument = [](const char *err) { throw std::invalid_argument{err}; };

memory_address_range::memory_address_range(const std::string &description, uint64_t start, uint64_t length,
    const pmas_flags &flags, const backing_store_config &backing_store,
    const memory_address_range_config &memory_config) try :
    address_range(description.c_str(), start, length, flags, throw_invalid_argument),
    m_mapped{std::max(memory_config.host_length, length), check_mmap_flags(flags, backing_store, memory_config),
        backing_store.data_filename, length},
    m_config{memory_config},
    m_backing_store{backing_store},
    // TODO(edubart): as an optimization we could detect newly created backing stores and pre-initialize
    // dirty hash tree as clean without even touching or causing page faults to the mapped memory
    m_dpt{get_level_count(length), static_cast<size_t>(length >> AR_LOG2_PAGE_SIZE), backing_store.dpt_filename,
        !backing_store.dpt_filename.empty() && backing_store.shared},
    m_dht{get_level_count(length), static_cast<size_t>(length >> AR_LOG2_PAGE_SIZE), backing_store.dht_filename,
        !backing_store.dht_filename.empty() && backing_store.shared} {
} catch (const std::exception &e) {
    throw std::invalid_argument{std::string{e.what()}.append(" when initializing ").append(description)};
} catch (...) {
    throw std::invalid_argument{"unknown exception when initializing "s.append(description)};
}

} // namespace cartesi
