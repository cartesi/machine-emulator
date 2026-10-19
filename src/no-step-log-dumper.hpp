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

#ifndef NO_STEP_LOG_DUMPER_HPP
#define NO_STEP_LOG_DUMPER_HPP

#include <cstdint>
#include <span>

#include "machine-hash.hpp"

namespace cartesi {

/// \brief No-op dump sink: the default Dumper of the replay accessors, so verification pays nothing
struct no_step_log_dumper {
    void begin_bracket(const char * /*text*/) const {}
    void end_bracket(const char * /*text*/) const {}
    void read(const char * /*name*/, uint64_t /*paddr*/, uint64_t /*val*/) const {}
    void write(const char * /*name*/, uint64_t /*paddr*/, uint64_t /*old_val*/, uint64_t /*new_val*/) const {}
    void write_hash(const char * /*name*/, uint64_t /*paddr*/, int /*log2_size*/, const_machine_hash_view /*old_hash*/,
        const_machine_hash_view /*new_hash*/, std::span<const unsigned char> /*data*/ = {}) const {}
    void write_bytes(const char * /*name*/, uint64_t /*paddr*/, int /*log2_size*/,
        std::span<const unsigned char> /*old_bytes*/, std::span<const unsigned char> /*new_bytes*/) const {}
    void revert(const_machine_hash_view /*root_hash*/) const {}
};

} // namespace cartesi

#endif
