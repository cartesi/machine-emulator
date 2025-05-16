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

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <system_error>

#include "address-range-constants.h"
#include "os-filesystem.h"
#include "unique-c-ptr.h"

namespace cartesi {

using namespace std::string_literals;

class base_error : public std::invalid_argument {
public:
    explicit base_error(const char *err) : std::invalid_argument{err} {
        ;
    }
};

memory_address_range::memory_address_range(const std::string &description, uint64_t start, uint64_t length,
    const pmas_flags &flags, const backing_store_config &backing_store, const memory_address_range_flags &ar_flags,
    uint64_t host_length) try :
    address_range(description.c_str(), start, length, flags, [](const char *err) { throw base_error{err}; }),
    m_ptr{make_unique_mmap<unsigned char>(host_length != 0 ? host_length : length,
        os_mmap_flags{
            .read_only = ar_flags.read_only && !backing_store.create && !backing_store.data_filename.empty(),
            .shared = backing_store.shared,
            .no_reserve = ar_flags.no_reserve,
        },
        backing_store.data_filename, length)},
    m_host_memory{m_ptr.get()},
    m_ar_flags{ar_flags},
    m_shared{backing_store.shared} {
    if (backing_store.shared && backing_store.data_filename.empty()) {
        throw std::invalid_argument{"shared backing store must have a filename"};
    }
    if (backing_store.create && !backing_store.shared) {
        throw std::invalid_argument{"created backing store must also be shared"};
    }
    if (backing_store.truncate && !backing_store.shared) {
        throw std::invalid_argument{"truncated backing store must also be shared"};
    }
    if (!is_memory()) {
        throw std::invalid_argument{"memory range must be flagged memory"s};
    }
    m_dirty_page_map.resize((get_length() / (8 * AR_PAGE_SIZE)) + 1, 0xff);
} catch (base_error &b) {
    throw; // already contains the description
} catch (std::exception &e) {
    throw std::invalid_argument{e.what() + " when initializing "s + description};
} catch (...) {
    throw std::invalid_argument{"unknown exception when initializing "s + description};
}

} // namespace cartesi
