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

#ifndef STEP_LOG_DUMPER_HPP
#define STEP_LOG_DUMPER_HPP

/// \file
/// \brief Dump sink that renders a replayed step log as indented, human-readable text.
/// The replay accessors feed it through their Dumper parameter; machine::dump_* drive it.

#include <cstdint>
#include <ostream>
#include <span>
#include <sstream>
#include <string>

#include "machine-hash.hpp"

namespace cartesi {

/// \brief Dump sink that formats a replayed uarch step as indented, human-readable text
class step_log_dumper {
    std::ostringstream m_out;
    bool m_muted{false}; ///< Drops output while set; bracket nesting still advances
    int m_indent{0};     ///< Current bracket nesting depth

    std::ostream &line() {
        return m_out << std::string(static_cast<size_t>(m_indent) * 2, ' ');
    }

public:
    /// \brief Returns the accumulated dump
    std::string str() const {
        return m_out.str();
    }

    void set_muted(bool muted) {
        m_muted = muted;
    }

    void begin_bracket(const char *text) {
        if (!m_muted) {
            line() << "begin " << text << '\n';
        }
        ++m_indent;
    }

    void end_bracket(const char *text) {
        --m_indent;
        if (!m_muted) {
            line() << "end " << text << '\n';
        }
    }

    /// \brief Emit a read. \p name is the register/field name; nullptr resolves it from the address.
    /// \details Values print as hex(decimal), e.g. 0x7b(123).
    void read(const char *name, uint64_t paddr, uint64_t val);

    /// \brief Emit a write, showing the value before and after. \p name and values as in read().
    void write(const char *name, uint64_t paddr, uint64_t old_val, uint64_t new_val);

    /// \brief Emit a bulk write witnessed only by its hash: the range's abbreviated hash before and after,
    /// plus a snippet of the written data when there is any
    void write_hash(const char *name, uint64_t paddr, int log2_size, const_machine_hash_view old_hash,
        const_machine_hash_view new_hash, std::span<const unsigned char> data = {});

    /// \brief Emit a bulk write of bytes: a snippet of the range before and of the data written
    void write_bytes(const char *name, uint64_t paddr, int log2_size, std::span<const unsigned char> old_bytes,
        std::span<const unsigned char> new_bytes);

    /// \brief Emit a revert of the whole state to a recorded root hash
    void revert(const_machine_hash_view root_hash);
};

} // namespace cartesi

#endif
