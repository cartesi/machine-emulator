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
#include <exception>
#include <stdexcept>
#include <system_error>

#include "address-range-constants.h"

namespace cartesi {

using namespace std::string_literals;

class base_error : public std::invalid_argument {
public:
    explicit base_error(const char *err) : std::invalid_argument{err} {
        ;
    }
};

static bool check_read_only(bool host_read_only, bool flags_W, bool create) {
    if (host_read_only) {
        if (create) {
            throw base_error{"newly-created backing store cannot be read-only"};
        }
        if (flags_W) {
            throw base_error{"backing store for writable memory address range cannot be read-only"};
        }
    }
    return host_read_only;
}

static const pmas_flags &check_flags(pmas_flags &&) = delete;
static const pmas_flags &check_flags(const pmas_flags &flags) {
    if (!flags.M) {
        throw base_error{"memory address range must be flagged memory"};
    }
    return flags;
}

static const auto throw_base_error = [](const char *err) { throw base_error{err}; };

memory_address_range::memory_address_range(const std::string &description, uint64_t start, uint64_t length,
    const pmas_flags &flags, const backing_store_config &backing_store,
    const memory_address_range_config &memory_config) try :
    address_range(description.c_str(), start, length, check_flags(flags), throw_base_error),
    m_ptr{make_unique_mmap<unsigned char>(std::max(memory_config.host_length, length),
        os_mmap_flags{
            .read_only = check_read_only(memory_config.host_read_only, flags.W, backing_store.create),
            .shared = backing_store.shared,
            .create = backing_store.create,
            .truncate = backing_store.truncate,
            .lock = !backing_store.data_filename.empty(),
        },
        backing_store.data_filename, length)},
    m_host_memory{m_ptr.get()},
    m_config{memory_config},
    m_dpt{get_level_count(length), length >> AR_LOG2_PAGE_SIZE},
    m_dht{get_level_count(length), length >> AR_LOG2_PAGE_SIZE} {
} catch (const base_error &b) {
    throw; // already contains the description
} catch (const std::exception &e) {
    throw std::invalid_argument{std::string{e.what()}.append(" when initializing ").append(description)};
} catch (...) {
    throw std::invalid_argument{"unknown exception when initializing "s.append(description)};
}

} // namespace cartesi
