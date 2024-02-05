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

#ifndef SLOG_H

#include <ostream>
#include <utility>

namespace slog {

/// \brief Encapsulates a stream and automatically adds end-of-line
struct autoendl {
    autoendl(std::ostream &out) : _out(out) {}

    template <class Rhs>
    autoendl &operator<<(Rhs &&rhs) {
        _out << std::forward<Rhs>(rhs);
        return *this;
    }

    autoendl &operator<<(std::ostream &(*manip)(std::ostream &) ) {
        manip(_out);
        return *this;
    }

    ~autoendl() {
        _out << std::endl;
    }

    autoendl(const autoendl &) = default;
    autoendl(autoendl &&) = default;
    autoendl &operator=(const autoendl &) = delete;
    autoendl &operator=(autoendl &&) = delete;

private:
    std::ostream &_out; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
};

/// \brief Operation for log_level function
enum class level_operation {
    get, ///> Get current level
    set  ///> Set current level
};

/// \brief Different log severity levels
enum class severity_level { trace, debug, info, warning, error, fatal };

/// \brief Get or set the current log level
/// \param operation Operation to perform. When level_operation::get, returns current level. When level_operation::set,
/// sets new level and returns previous level.
/// \param new_level New level for level_operation::set.
/// \returns Current level for level_operation::get or previous level for level_operation::set.
severity_level log_level(level_operation operation, severity_level new_level = severity_level::trace);

/// \brief Dummy log prefix that prints nothing
static inline std::ostream &log_prefix(std::ostream &out) {
    return out;
}

/// \brief Gets the name of a log severity level
/// \param level The log severity level
/// \returns The corresponding name
const char *to_string(severity_level level);

/// \brief Gets the name of a log severity level or throws error if invalid
/// \param name Name of the log severity level
/// \returns The corresponding enumeration
severity_level from_string(const char *name);

/// \brief Class that prints nothing as prefix
struct null_prefix {
    severity_level level;
};

/// \brief Stream-out operator for null prefix class
static inline std::ostream &operator<<(std::ostream &out, null_prefix) {
    return out;
}

/// \brief Redefine to change log prefix (default prints nothing)
#ifndef SLOG_PREFIX
#define SLOG_PREFIX null_prefix
#endif

/// \brief Redefine to change log output stream (default is std::clog)
#ifndef SLOG_OSTREAM
#define SLOG_OSTREAM std::clog
#endif

/// \brief Set to true to suppress all log at compile time
#ifndef SLOG_DISABLE
#define SLOG_DISABLE (false)
#endif

/// \brief Outputs a log entry
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SLOG(level)                                                                                                    \
    if (SLOG_DISABLE || slog::severity_level::level < slog::log_level(slog::level_operation::get)) {                   \
    } else                                                                                                             \
        slog::autoendl(SLOG_OSTREAM) << SLOG_PREFIX {                                                                  \
            slog::severity_level::level                                                                                \
        }

} // namespace slog

#endif
