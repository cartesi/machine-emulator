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

#ifndef STEP_DUMPER_HPP
#define STEP_DUMPER_HPP

/// \file
/// \brief Human-readable dump of a replayed uarch step log.

#include <cstdint>
#include <ostream>
#include <span>
#include <sstream>
#include <string>

namespace cartesi {

/// \brief Dump sink that formats a replayed uarch step as indented, human-readable text
class step_dumper {
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

    /// \brief Emit a read. \p name is the register/field name, or nullptr for plain memory.
    /// \details Values print as hex(decimal), e.g. 0x7b(123).
    void read(const char *name, uint64_t paddr, uint64_t val) {
        if (m_muted) {
            return;
        }
        line() << "read " << (name != nullptr ? name : "") << "@0x" << std::hex << paddr << ": 0x" << val << std::dec
               << '(' << val << ")\n";
    }

    /// \brief Emit a write, showing the value before and after. \p name and values as in read().
    void write(const char *name, uint64_t paddr, uint64_t old_val, uint64_t new_val) {
        if (m_muted) {
            return;
        }
        line() << "write " << (name != nullptr ? name : "") << "@0x" << std::hex << paddr << ": 0x" << old_val
               << std::dec << '(' << old_val << ") -> 0x" << std::hex << new_val << std::dec << '(' << new_val << ")\n";
    }
};

/// \brief Replays a uarch step log and returns a human-readable dump
/// \param log Binary step log produced by machine::log_step_uarch
/// \param skip_count Number of cycles to replay silently first
/// \param uarch_cycle_count Number of cycles to dump after those; stops early if the uarch halts
/// \details No caller claim is checked. Each replayed cycle is bracketed, and a dump with a skip is the
/// matching slice of the dump without one.
std::string dump_step_uarch(std::span<const unsigned char> log, uint64_t skip_count, uint64_t uarch_cycle_count);

} // namespace cartesi

#endif
