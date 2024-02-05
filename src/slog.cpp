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

#include "slog.h"

#include <cstring>

namespace slog {

severity_level log_level(level_operation operation, severity_level new_level) {
    static severity_level level = severity_level::trace;
    if (operation == level_operation::set) {
        auto old_level = level;
        level = new_level;
        return old_level;
    }
    return level;
}

const char *to_string(severity_level level) {
    switch (level) {
        case severity_level::trace:
            return "trace";
        case severity_level::debug:
            return "debug";
        case severity_level::info:
            return "info";
        case severity_level::warning:
            return "warning";
        case severity_level::error:
            return "error";
        case severity_level::fatal:
            return "fatal";
        default:
            return "unknown";
    }
}

severity_level from_string(const char *name) {
    if (strcmp(name, "trace") == 0) {
        return severity_level::trace;
    }
    if (strcmp(name, "debug") == 0) {
        return severity_level::debug;
    }
    if (strcmp(name, "info") == 0) {
        return severity_level::info;
    }
    if (strcmp(name, "warning") == 0) {
        return severity_level::warning;
    }
    if (strcmp(name, "error") == 0) {
        return severity_level::error;
    }
    if (strcmp(name, "fatal") == 0) {
        return severity_level::fatal;
    }
    throw std::domain_error{"unknown log severity level"};
}

} // namespace slog
