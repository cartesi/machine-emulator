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

#ifndef STEP_PRETTY_PRINTER_HPP
#define STEP_PRETTY_PRINTER_HPP

/// \file
/// \brief Human-readable printout of a replayed step.

#include <cstdint>
#include <ostream>
#include <sstream>
#include <string>

namespace cartesi {

/// \brief Sink that formats a step replay as an indented, human-readable printout.
/// \details Each instruction is bracketed by its mnemonic, with its reads and writes nested
/// underneath. Host-only (it allocates).
class step_pretty_printer {
    std::ostringstream m_out;
    int m_indent{0};      ///< Current bracket nesting depth
    uint64_t m_access{0}; ///< 1-based access counter across the whole printout

    std::ostream &line() {
        return m_out << std::string(static_cast<size_t>(m_indent) * 2, ' ');
    }

public:
    /// \brief Returns the accumulated printout.
    std::string str() const {
        return m_out.str();
    }

    void begin_bracket(const char *text) {
        line() << "begin " << text << '\n';
        ++m_indent;
    }

    void end_bracket(const char *text) {
        --m_indent;
        line() << "end " << text << '\n';
    }

    /// \brief Emit a read. \p name is the register/field name, or nullptr for plain memory.
    /// \details Values print as hex(decimal), e.g. 0x7b(123).
    void read(const char *name, uint64_t paddr, uint64_t val) {
        line() << std::dec << ++m_access << ": read " << (name != nullptr ? name : "") << "@0x" << std::hex << paddr
               << ": 0x" << val << std::dec << '(' << val << ")\n";
    }

    /// \brief Emit a write, showing the value before and after. \p name and values as in read().
    void write(const char *name, uint64_t paddr, uint64_t old_val, uint64_t new_val) {
        line() << std::dec << ++m_access << ": write " << (name != nullptr ? name : "") << "@0x" << std::hex << paddr
               << ": 0x" << old_val << std::dec << '(' << old_val << ") -> 0x" << std::hex << new_val << std::dec << '('
               << new_val << ")\n";
    }
};

} // namespace cartesi

#endif
