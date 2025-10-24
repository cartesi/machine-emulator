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

#ifndef MACHINE_CONSOLE_H
#define MACHINE_CONSOLE_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include "machine-runtime-config.h"
#include "os.h"
#include "unique-c-ptr.h"

/// \file
/// \brief Machine console implementation.

namespace cartesi {

/// \brief Exception thrown for I/O console errors
class machine_console_exception : public std::system_error {
public:
    /// \brief Constructor from error message.
    /// \param message Error message.
    machine_console_exception(int ev, const std::string &message) :
        std::system_error{ev, std::generic_category(), message} {}
};

/// \brief Machine console class that handles console input/output with various sources and destinations.
class machine_console final {
public:
    static constexpr uint8_t END_OF_TRANSMISSION_CHAR = 4;

    /// \brief Constructor from console runtime configuration.
    /// \param config Console runtime configuration.
    explicit machine_console(const console_runtime_config &config);

    /// \brief No default constructor.
    machine_console() = delete;
    /// \brief No copy constructor.
    machine_console(const machine_console &other) = delete;
    /// \brief No move constructor.
    machine_console(machine_console &&other) = delete;
    /// \brief No copy assignment.
    machine_console &operator=(const machine_console &other) = delete;
    /// \brief No move assignment.
    machine_console &operator=(machine_console &&other) = delete;

    /// \brief Destructor.
    ~machine_console() noexcept;

    /// \brief Writes multiple characters to console output.
    /// \param buf Buffer of characters to write.
    /// \returns True if console output should be flushed externally.
    bool putchars(std::span<const uint8_t> buf) noexcept;

    /// \brief Writes a character to console output.
    /// \param ch Character to write.
    /// \returns True if console output should be flushed externally.
    bool putchar(uint8_t ch) noexcept {
        return putchars(std::span<const uint8_t>{&ch, 1});
    }

    /// \brief Reads multiple characters from console input.
    /// \param buf Buffer to receive characters.
    /// \returns The number of characters actually read into the buffer,
    /// 0 if no characters are available to read (input is idle).
    /// Followed by a bool indicating if the input needs refilling.
    /// \details If input is closed, fills the buffer with END_OF_TRANSMISSION_CHAR (4).
    std::pair<size_t, bool> getchars(std::span<uint8_t> buf) noexcept;

    /// \brief Reads a character from console input.
    /// \returns The character read as an unsigned 8-bit integer (0-255),
    /// or -1 if no character is available (input is idle),
    /// or END_OF_TRANSMISSION_CHAR (value 4) if the input has been closed (EOF).
    /// Followed by a bool indicating if the input needs refilling.
    std::pair<int, bool> getchar() noexcept;

    /// \brief Fill file descriptors to be polled by select() with console file descriptors.
    /// \param fds Pointer to sets of read, write and except file descriptors to be updated.
    void prepare_select(os::select_fd_sets *fds) const noexcept;

    /// \brief Poll console file descriptors that were marked as ready by select().
    /// \param select_ret Return value from the most recent select() call.
    /// \param fds Pointer to sets of read, write and except file descriptors to be checked.
    /// \returns True if there are pending input characters available to be read, false otherwise.
    bool poll_selected(int select_ret, os::select_fd_sets *fds) const noexcept;

    /// \brief Polls console for input characters.
    /// \param timeout_us Timeout to wait for characters in microseconds.
    /// \returns True if there are pending input characters available to be read, false otherwise.
    bool poll(uint64_t timeout_us) const noexcept;

    /// \brief Reads console output buffer data.
    /// \param data Pointer to buffer receiving the console output data.
    /// \param max_length Maximum number of bytes to read (0 to query available size).
    /// \returns Number of bytes actually read from the buffer.
    uint64_t read_output(uint8_t *data, uint64_t max_length);

    /// \brief Writes console input buffer data.
    /// \param data Pointer to data to write to the console input buffer.
    /// \param length Number of bytes to write (0 to query available space).
    /// \returns Number of bytes actually written to the buffer.
    uint64_t write_input(const uint8_t *data, uint64_t length);

    /// \brief Updates the console runtime configuration.
    /// \param config New console runtime configuration.
    void set_config(const console_runtime_config &config);

    /// \brief Get console size.
    /// \returns Console size as a pair of [columns, rows].
    std::pair<uint16_t, uint16_t> get_size() const noexcept;

    /// \brief Flushes the output buffer to the configured output destination.
    /// \throws machine_console_exception on I/O errors.
    void flush_output();

    /// \brief Clears the output buffer without flushing.
    void clear_output() noexcept;

    /// \brief Refills the input buffer from the configured input source.
    /// \throws machine_console_exception on I/O errors.
    void refill_input();

    /// \brief Returns available space in the input buffer.
    size_t available_input_buffer_space() const noexcept {
        return (m_input_buffer.size() > static_cast<size_t>(m_input_size)) ?
            (m_input_buffer.size() - static_cast<size_t>(m_input_size)) :
            0;
    }

    /// \brief Returns available space in the output buffer.
    size_t available_output_buffer_space() const noexcept {
        return (m_output_buffer.size() > static_cast<size_t>(m_output_size)) ?
            (m_output_buffer.size() - static_cast<size_t>(m_output_size)) :
            0;
    }

    /// \brief Returns the current console output destination.
    console_output_destination get_output_destination() const noexcept {
        return m_output_destination;
    }

    /// \brief Returns the current console input source.
    console_input_source get_input_source() const noexcept {
        return m_input_source;
    }

    /// \brief Checks if there are characters available to read from console input.
    bool is_input_ready() const noexcept {
        return m_input_size > 0 || m_input_closed;
    }

private:
    // Output
    console_output_destination m_output_destination{console_output_destination::to_stdout}; ///< Output destination
    console_flush_mode m_output_flush_mode{console_flush_mode::every_line};                 ///< Output flush mode
    int m_output_fd{-1};                  ///< Output file descriptor (when writing to fd)
    std::string m_output_filename;        ///< Output file name (when writing to file)
    unique_file_ptr m_output_file;        ///< Output file handle (when writing to file)
    std::vector<uint8_t> m_output_buffer; ///< Pre-allocated output buffer for buffered console output
    std::ptrdiff_t m_output_start{0};     ///< Start index of valid data in output buffer
    std::ptrdiff_t m_output_size{0};      ///< Number of valid bytes in output buffer

    // Input
    console_input_source m_input_source{console_input_source::from_null}; ///< Input source
    int m_input_fd{-1};                  ///< Input file descriptor (when writing to fd)
    std::string m_input_filename;        ///< Input file name (when reading from file)
    unique_file_ptr m_input_file;        ///< Input file handle (when reading from file)
    std::vector<uint8_t> m_input_buffer; ///< Pre-allocated input buffer for buffered console input
    std::ptrdiff_t m_input_start{0};     ///< Start index of valid data in input buffer
    std::ptrdiff_t m_input_size{0};      ///< Number of valid bytes in input buffer
    bool m_input_closed{true};           ///< True if input is closed (reached EOF or got an error)
    bool m_input_tty_opened{false};      ///< True if input is from TTY and TTY was opened

    uint16_t m_tty_cols{os::TTY_DEFAULT_COLS}; ///< TTY columns
    uint16_t m_tty_rows{os::TTY_DEFAULT_ROWS}; ///< TTY rows

    /// \brief Consumes bytes from the output buffer.
    /// \param n Number of bytes to consume.
    /// \returns Span of consumed bytes.
    std::span<const uint8_t> consume_output(size_t n) noexcept;

    /// \brief Consumes bytes from the input buffer.
    /// \param n Number of bytes to consume.
    /// \returns Span of consumed bytes.
    std::span<const uint8_t> consume_input(size_t n) noexcept;

    /// \brief Appends data to the output buffer.
    /// \param buf Buffer of data to append.
    /// \returns Subspan of data that was actually appended.
    /// \details It may truncate characters if the output buffer lacks space.
    std::span<const uint8_t> append_output(std::span<const uint8_t> buf) noexcept;

    /// \brief Appends data to the input buffer.
    /// \param buf Buffer of data to append.
    /// \returns Subspan of data that was actually appended.
    /// \details It may truncate characters if the input buffer lacks space.
    std::span<const uint8_t> append_input(std::span<const uint8_t> buf) noexcept;

    /// \brief Opens output file or file descriptor based on configuration.
    /// \param config Configuration to use for opening the output.
    void open_output(const console_runtime_config &config);

    /// \brief Closes output file or file descriptor.
    void close_output() noexcept;

    /// \brief Opens input file or file descriptor based on configuration.
    /// \param config Configuration to use for opening the input.
    void open_input(const console_runtime_config &config);

    /// \brief Closes input file or file descriptor.
    void close_input() noexcept;

    /// \brief Validates the console runtime configuration.
    /// \param config Configuration to validate.
    /// \throws std::invalid_argument if configuration is invalid.
    static void validate_config(const console_runtime_config &config);
};

} // namespace cartesi

#endif
