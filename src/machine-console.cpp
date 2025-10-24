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

#include "machine-console.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <span>
#include <stdexcept>
#include <utility>

#include "machine-runtime-config.h"
#include "os.h"
#include "unique-c-ptr.h"

namespace cartesi {

machine_console::machine_console(const console_runtime_config &config) :
    m_tty_cols{config.tty_cols},
    m_tty_rows{config.tty_rows} {
    validate_config(config);
    open_input(config);
    open_output(config);
}

machine_console::~machine_console() noexcept {
    try {
        // Flush any remaining output before destruction
        flush_output();
    } catch (...) { // NOLINT(bugprone-empty-catch)
        // Guard against exceptions here, because we can't to throw exceptions on destruction.
    }
    close_output();
    close_input();
}

bool machine_console::putchars(std::span<const uint8_t> buf) noexcept {
    // Return early if there's no data to write
    if (buf.empty() || m_output_destination == console_output_destination::to_null) {
        return false;
    }

    // Append data to output buffer
    buf = append_output(buf);

    // Check if we should flush based on flush mode
    bool should_flush = available_output_buffer_space() == 0;
    switch (m_output_flush_mode) {
        case console_flush_mode::when_full: // Flush only when buffer is full
            break;
        case console_flush_mode::every_char: // Flush on new character
            should_flush = true;
            break;
        case console_flush_mode::every_line: // Flush on newline or when buffer is full
            should_flush |= std::ranges::find(buf, '\n') != buf.end();
            break;
    }

    // Returning true here should break the machine interpreter,
    // and eventually either machine run will call flush_output() ro the user will consume the console outputs.
    return should_flush;
}

std::pair<size_t, bool> machine_console::getchars(std::span<uint8_t> buf) noexcept {
    // Return end of transmission character in case the input was closed
    if (m_input_closed) {
        std::ranges::fill(buf, END_OF_TRANSMISSION_CHAR);
        return {buf.size(), false};
    }

    // Consume input buffer
    auto input_chunk = consume_input(buf.size());
    if (!input_chunk.empty()) {
        std::ranges::copy(input_chunk.begin(), input_chunk.end(), buf.begin());
    }

    // Request refill if input buffer is now empty
    const bool should_refill = m_input_size == 0 && !m_input_closed;
    return {input_chunk.size(), should_refill};
}

std::pair<int, bool> machine_console::getchar() noexcept {
    std::array<uint8_t, 1> buf{};
    const auto [n, should_refill] = getchars(buf);
    if (n == 0) { // No input
        return {-1, should_refill};
    }
    return {buf[0], should_refill};
}

void machine_console::prepare_select(os::select_fd_sets *fds) const noexcept {
    // When input is closed, there is no need to select file descriptors
    if (m_input_closed) {
        return;
    }

    switch (m_input_source) {
        case console_input_source::from_stdin:
            os::prepare_tty_select(fds);
            break;
        case console_input_source::from_fd:
            os::prepare_fd_select(fds, m_input_fd);
            break;
        case console_input_source::from_null:
        case console_input_source::from_file:
        case console_input_source::from_buffer:
            // Nothing to prepare
            break;
    }
}

bool machine_console::poll_selected(int select_ret, os::select_fd_sets *fds) const noexcept {
    // When input is closed, there is nothing to poll
    if (m_input_closed) {
        return false;
    }

    // Check if input is available to read
    switch (m_input_source) {
        case console_input_source::from_stdin:
            return os::poll_selected_tty(select_ret, fds);
        case console_input_source::from_fd:
            return os::poll_selected_fd(select_ret, fds, m_input_fd);
        case console_input_source::from_file:
            return true; // Input from files always needs to be refilled until EOF
        case console_input_source::from_buffer:
            return m_input_size == 0; // Input from buffer needs to be refilled when empty
        case console_input_source::from_null:
            return false;
    }
    return false;
}

bool machine_console::poll(uint64_t timeout_us) const noexcept {
    // When input is closed, there is nothing to poll
    if (m_input_closed) {
        return false;
    }

    switch (m_input_source) {
        case console_input_source::from_stdin:
            return os::poll_tty(timeout_us);
        case console_input_source::from_fd:
            return os::select_fds([this](os::select_fd_sets *fds,
                                      uint64_t * /*timeout_us*/) -> void { os::prepare_fd_select(fds, m_input_fd); },
                [this](int select_ret, os::select_fd_sets *fds) -> bool {
                    return os::poll_selected_fd(select_ret, fds, m_input_fd);
                },
                &timeout_us);
        case console_input_source::from_file:
            return true; // Input from files always needs to be refilled until EOF
        case console_input_source::from_buffer:
            if (m_input_size == 0) {
                // Sleep when idle, otherwise the interpreter would use a lot of CPU in buffer mode
                os::sleep_us(timeout_us);
            }
            return m_input_size == 0; // Input from buffer needs to be refilled when empty
        case console_input_source::from_null:
            return false;
    }

    return false;
}

uint64_t machine_console::read_output(uint8_t *data, uint64_t max_length) {
    if (m_output_destination != console_output_destination::to_buffer) {
        throw std::invalid_argument{"console output destination is not using a buffer"};
    }

    // Query mode: return available size without consuming data
    if (data == nullptr || max_length == 0) {
        return m_output_size;
    }

    const auto to_read = std::min(m_output_size, static_cast<ptrdiff_t>(max_length));

    if (to_read > 0) {
        if (data == nullptr) {
            throw std::invalid_argument{"invalid pointer for console input"};
        }
        auto output_chunk = consume_output(to_read);
        std::ranges::copy(output_chunk.begin(), output_chunk.end(), data);
        return output_chunk.size();
    }

    return 0;
}

uint64_t machine_console::write_input(const uint8_t *data, uint64_t length) {
    if (m_input_source != console_input_source::from_buffer) {
        throw std::invalid_argument{"console input source is not using a buffer"};
    }

    // Query mode: return available space without writing data
    if (data == nullptr || length == 0) {
        return available_input_buffer_space();
    }

    if (data == nullptr) {
        throw std::invalid_argument{"invalid pointer for console input"};
    }

    return append_input(std::span<const uint8_t>{data, static_cast<size_t>(length)}).size();
}

void machine_console::set_config(const console_runtime_config &config) {
    validate_config(config);

    const bool output_changed = (m_output_destination != config.output_destination) ||
        (m_output_fd != config.output_fd) || (m_output_filename != config.output_filename) ||
        (m_output_flush_mode != config.output_flush_mode) || (config.output_buffer_size != m_output_buffer.size());
    if (output_changed) {
        flush_output();
        close_output();
        open_output(config);
    }

    const bool input_changed = (m_input_source != config.input_source) || (m_input_fd != config.input_fd) ||
        (m_input_filename != config.input_filename) || (config.input_buffer_size != m_input_buffer.size());
    if (input_changed) {
        close_input();
        open_input(config);
    }

    m_tty_cols = config.tty_cols;
    m_tty_rows = config.tty_rows;
}

std::pair<uint16_t, uint16_t> machine_console::get_size() const noexcept {
    if (m_input_source == console_input_source::from_stdin) {
        return os::get_tty_size();
    }
    return {m_tty_cols, m_tty_rows};
}

void machine_console::flush_output() {
    if (m_output_size == 0) {
        return;
    }

    const auto output_chunk = std::span<const uint8_t>{m_output_buffer}.subspan(m_output_start, m_output_size);
    ptrdiff_t consumed_bytes{0};

    // Flush the buffer to the appropriate destination
    switch (m_output_destination) {
        case console_output_destination::to_null:
            consumed_bytes = static_cast<ptrdiff_t>(m_output_size);
            break;
        case console_output_destination::to_stdout:
            consumed_bytes = os::putchars(output_chunk, os::tty_output::to_stdout);
            break;
        case console_output_destination::to_stderr:
            consumed_bytes = os::putchars(output_chunk, os::tty_output::to_stderr);
            break;
        case console_output_destination::to_fd:
            consumed_bytes = os::write_fd(m_output_fd, output_chunk);
            break;
        case console_output_destination::to_file:
            errno = 0;
            consumed_bytes =
                static_cast<ptrdiff_t>(fwrite(output_chunk.data(), 1, output_chunk.size(), m_output_file.get()));
            if (consumed_bytes > 0) {
                if (fflush(m_output_file.get()) != 0) {
                    consume_output(static_cast<size_t>(consumed_bytes));
                    consumed_bytes = -1;
                }
            } else if (ferror(m_output_file.get()) != 0) {
                consumed_bytes = -1;
            }
            // On Linux errno should be set when fwrite()/fflush() fails, although this is not documented,
            // however if it wasn't set then assume there was an IO error
            if (consumed_bytes < 0 && errno == 0) {
                errno = EIO;
            }
            break;
        case console_output_destination::to_buffer:
            // Nothing to do, user must consume the buffer.
            break;
    }

    if (consumed_bytes < 0) {
        if (errno == EPIPE) { // Output was closed externally
            // Ignore and consume all output silently
            m_output_size = 0;
            m_output_start = 0;
        } else {
            throw machine_console_exception{errno, "console output flush failed"};
        }
    } else if (consumed_bytes > 0) {
        consume_output(static_cast<size_t>(consumed_bytes));
    }
}

void machine_console::clear_output() noexcept {
    m_output_size = 0;
    m_output_start = 0;
}

void machine_console::refill_input() {
    // Return early if there's already characters in the input buffer
    if (m_input_size > 0) {
        return;
    }

    // Can't refill if input is closed
    if (m_input_closed) {
        return;
    }

    m_input_start = 0;
    const auto input_chunk = std::span<uint8_t>{m_input_buffer};
    ptrdiff_t appended_bytes{0};

    switch (m_input_source) {
        case console_input_source::from_null:
            break;
        case console_input_source::from_stdin:
            // Check if there are characters ready to be read before
            if (os::poll_tty(0)) {
                appended_bytes = os::getchars(input_chunk);
                m_input_closed = appended_bytes < 0;
            }
            break;
        case console_input_source::from_fd: {
            // Check if there are characters ready to be read before
            uint64_t timeout_us = 0;
            if (os::select_fds([this](os::select_fd_sets *fds,
                                   uint64_t * /*timeout_us*/) -> void { os::prepare_fd_select(fds, m_input_fd); },
                    [this](int select_ret, os::select_fd_sets *fds) -> bool {
                        return os::poll_selected_fd(select_ret, fds, m_input_fd);
                    },
                    &timeout_us)) {
                appended_bytes = os::read_fd(m_input_fd, input_chunk);
                m_input_closed = appended_bytes <= 0;
            }
            break;
        }
        case console_input_source::from_file: {
            errno = 0;
            const auto nread = fread(input_chunk.data(), 1, input_chunk.size(), m_input_file.get());
            m_input_closed = nread == 0;
            if (nread == 0 && feof(m_input_file.get()) != 0) {
                appended_bytes = -1;
                errno = EPIPE;
            } else if (nread == 0 && ferror(m_input_file.get()) != 0) {
                appended_bytes = -1;
                // On Linux errno should be set when fread() fails, although this is not documented,
                // however if it wasn't set then assume there was an IO error
                if (errno == 0) {
                    errno = EIO;
                }
            } else {
                appended_bytes = static_cast<ptrdiff_t>(nread);
            }
            break;
        }
        case console_input_source::from_buffer:
            break;
    }

    if (appended_bytes < 0) {
        if (errno == EPIPE) { // Input was closed externally
            // Ignore silently
        } else {
            throw machine_console_exception{errno, "console input refill failed"};
        }
    } else if (appended_bytes > 0) {
        m_input_size = appended_bytes;
    }
}

std::span<const uint8_t> machine_console::consume_output(size_t n) noexcept {
    const ptrdiff_t chunk_len = std::min(static_cast<ptrdiff_t>(n), m_output_size);
    auto chunk_buf = std::span<const uint8_t>(m_output_buffer).subspan(m_output_start, chunk_len);
    m_output_start += chunk_len;
    m_output_size -= chunk_len;
    if (m_output_size == 0) {
        m_output_start = 0;
    }
    return chunk_buf;
}

std::span<const uint8_t> machine_console::consume_input(size_t n) noexcept {
    const ptrdiff_t chunk_len = std::min(static_cast<ptrdiff_t>(n), m_input_size);
    auto chunk_buf = std::span<const uint8_t>(m_input_buffer).subspan(m_input_start, chunk_len);
    m_input_start += chunk_len;
    m_input_size -= chunk_len;
    if (m_input_size == 0) {
        m_input_start = 0;
    }
    return chunk_buf;
}

std::span<const uint8_t> machine_console::append_output(std::span<const uint8_t> buf) noexcept {
    // Make room by discarding oldest data if the output buffer is too small
    if (m_output_size + buf.size() > m_output_buffer.size()) {
        // This situation is unlikely to occur in normal machine configurations,
        // but this safeguard is necessary to prevent buffer overflows.
        std::ignore = std::fprintf(stderr,
            "WARNING: console output buffer is out of space, some output characters were truncated\n");
        std::ignore = consume_output((m_output_size + buf.size()) - m_output_buffer.size());

        // In case the buf is very big, then it needs to be truncated
        buf = buf.subspan(0, std::min(buf.size(), available_output_buffer_space()));
    }

    // Move buffer towards to the left when needed
    if (m_output_start > 0 && m_output_start + m_output_size + buf.size() > m_output_buffer.size()) {
        if (m_output_size > 0) {
            // C++ std::ranges::copy_n safely handles overlapping memory when moving memory to the left
            std::ranges::copy_n(std::next(m_output_buffer.begin(), m_output_start), m_output_size,
                m_output_buffer.begin());
        }
        m_output_start = 0;
    }

    // Append new data
    std::ranges::copy(buf, std::next(m_output_buffer.begin(), m_output_start + m_output_size));
    m_output_size += static_cast<ptrdiff_t>(buf.size());
    return buf;
}

std::span<const uint8_t> machine_console::append_input(std::span<const uint8_t> buf) noexcept {
    // Append partial data to the buffer if there is not enough available space
    buf = buf.subspan(0, std::min(buf.size(), available_input_buffer_space()));
    if (buf.empty()) {
        return buf;
    }

    // Move buffer towards to the left when needed
    if (m_input_start > 0 && m_input_start + m_input_size + buf.size() > m_input_buffer.size()) {
        if (m_input_size > 0) {
            // C++ std::ranges::copy_n safely handles overlapping memory when moving memory to the left
            std::ranges::copy_n(std::next(m_input_buffer.begin(), m_input_start), m_input_size, m_input_buffer.begin());
        }
        m_input_start = 0;
    }

    // Append new data
    std::ranges::copy(buf, std::next(m_input_buffer.begin(), m_input_start + m_input_size));
    m_input_size += static_cast<ptrdiff_t>(buf.size());
    return buf;
}

void machine_console::open_output(const console_runtime_config &config) {
    if (config.output_buffer_size < m_output_buffer.size()) {
        throw std::invalid_argument{"shrinking runtime console output buffer size is not allowed"};
    }
    switch (config.output_destination) {
        case console_output_destination::to_null:
        case console_output_destination::to_stdout:
        case console_output_destination::to_stderr:
        case console_output_destination::to_buffer:
            break;
        case console_output_destination::to_fd:
            m_output_fd = os::dup_fd(config.output_fd);
            break;
        case console_output_destination::to_file:
            m_output_file = make_unique_fopen(config.output_filename.c_str(), "ab");
            m_output_filename = config.output_filename;
            break;
    }
    m_output_destination = config.output_destination;
    m_output_flush_mode = config.output_flush_mode;
    if (config.output_buffer_size > m_output_buffer.size()) {
        m_output_buffer.resize(config.output_buffer_size);
    }
}

void machine_console::close_output() noexcept {
    if (m_output_fd != -1) {
        os::close_fd(m_output_fd);
        m_output_fd = -1;
    }
    m_output_file.reset();
    m_output_filename.clear();
    m_output_destination = console_output_destination::to_null;
}

void machine_console::open_input(const console_runtime_config &config) {
    if (config.input_buffer_size < m_input_buffer.size()) {
        throw std::invalid_argument{"shrinking runtime console input buffer size is not allowed"};
    }
    switch (config.input_source) {
        case console_input_source::from_null:
            break;
        case console_input_source::from_stdin:
            os::open_tty();
            m_input_tty_opened = true;
            break;
        case console_input_source::from_fd:
            m_input_fd = os::dup_fd(config.input_fd);
            break;
        case console_input_source::from_file:
            m_input_file = make_unique_fopen(config.input_filename.c_str(), "rb");
            m_input_filename = config.input_filename;
            break;
        case console_input_source::from_buffer:
            break;
    }
    m_input_source = config.input_source;
    m_input_closed = config.input_source == console_input_source::from_null;
    if (config.input_buffer_size > m_input_buffer.size()) {
        m_input_buffer.resize(config.input_buffer_size);
    }
    refill_input();
}

void machine_console::close_input() noexcept {
    if (m_input_tty_opened) {
        os::close_tty();
        m_input_tty_opened = false;
    }
    if (m_input_fd != -1) {
        os::close_fd(m_input_fd);
        m_input_fd = -1;
    }
    m_input_file.reset();
    m_input_filename.clear();
    m_input_source = console_input_source::from_null;
    m_input_closed = true;
}

void machine_console::validate_config(const console_runtime_config &config) {
    if (!config.output_filename.empty() && config.output_destination != console_output_destination::to_file) {
        throw std::invalid_argument{"console output filename must not be set"};
    }
    if (!config.input_filename.empty() && config.input_source != console_input_source::from_file) {
        throw std::invalid_argument{"console input filename must not be set"};
    }
    if (config.output_fd != -1 && config.output_destination != console_output_destination::to_fd) {
        throw std::invalid_argument{"console output fd must not be set"};
    }
    if (config.input_fd != -1 && config.input_source != console_input_source::from_fd) {
        throw std::invalid_argument{"console input fd must not be set"};
    }
    if (config.output_buffer_size == 0) {
        throw std::invalid_argument{"console output buffer size must be greater than 0"};
    }
    if (config.input_buffer_size == 0) {
        throw std::invalid_argument{"console input buffer size must be greater than 0"};
    }
}

} // namespace cartesi
