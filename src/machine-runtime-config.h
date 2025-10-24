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

#ifndef MACHINE_RUNTIME_CONFIG_H
#define MACHINE_RUNTIME_CONFIG_H

#include <cstdint>
#include <string>

#include "os.h"

/// \file
/// \brief Runtime configuration for machines.

namespace cartesi {

/// \brief Console output destination
enum class console_output_destination {
    to_null,   ///< Write to nowhere (no console output)
    to_stdout, ///< Write to host's stdout
    to_stderr, ///< Write to host's stderr
    to_fd,     ///< Write to a host's file descriptor
    to_file,   ///< Write to a host's file
    to_buffer, ///< Write to internal buffer
};

/// \brief Console flush mode
enum class console_flush_mode {
    when_full,  ///< Flush when buffer is full
    every_char, ///< Flush after every new character
    every_line, ///< Flush after every new line (or when buffer is full)
};

/// \brief Console input source
enum class console_input_source {
    from_null,   ///< Read from nowhere (no console input)
    from_stdin,  ///< Read from host's stdin
    from_fd,     ///< Read from a host's file descriptor
    from_file,   ///< Read from a host's file
    from_buffer, ///< Read from internal buffer
};

/// \brief Console runtime configuration
struct console_runtime_config {
    // Output
    console_output_destination output_destination{console_output_destination::to_stdout}; ///< Output destination
    console_flush_mode output_flush_mode{console_flush_mode::every_line};                 ///< Output flush mode
    uint64_t output_buffer_size{4096};                                                    ///< Output buffer size
    int32_t output_fd{-1};                                                                ///< Output file descriptor
    std::string output_filename;                                                          ///< Output file name

    // Input
    console_input_source input_source{console_input_source::from_null}; ///< Input source
    uint64_t input_buffer_size{4096};                                   ///< Input buffer size
    int32_t input_fd{-1};                                               ///< Input file descriptor
    std::string input_filename;                                         ///< Input file name

    // TTY
    uint16_t tty_cols{os::TTY_DEFAULT_COLS}; ///< TTY columns
    uint16_t tty_rows{os::TTY_DEFAULT_ROWS}; ///< TTY rows
};

/// \brief Concurrency runtime configuration
struct concurrency_runtime_config {
    uint64_t update_hash_tree{};
};

/// \brief Machine runtime configuration
struct machine_runtime_config {
    console_runtime_config console{};
    concurrency_runtime_config concurrency{};
    bool skip_version_check{};
    bool soft_yield{};
    bool no_reserve{}; ///< Do not reserve swap memory when mapping flash drives
};

} // namespace cartesi

#endif
