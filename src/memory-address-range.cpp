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

namespace cartesi {

using namespace std::string_literals;

class base_error : public std::invalid_argument {
public:
    explicit base_error(const char *err) : std::invalid_argument{err} {
        ;
    }
};

memory_address_range::memory_address_range(const std::string &description, uint64_t start, uint64_t length,
    const pmas_flags &flags, const std::string &image_filename, const mmapd &m) try :
    address_range(description.c_str(), start, length, flags, [](const char *err) { throw base_error{err}; }),
    m_ptr{make_unique_mmap<unsigned char>(image_filename.c_str(), length, m.shared)},
    m_host_memory{std::get<mmapd_ptr>(m_ptr).get()} {
    if (!is_memory()) {
        throw std::invalid_argument{"memory range must be flagged memory when initializing "s + description};
    }
    m_dirty_page_map.resize((get_length() / (8 * AR_PAGE_SIZE)) + 1, 0xff);
} catch (base_error &b) {
    throw; // already contains the description
} catch (std::exception &e) {
    throw std::invalid_argument{e.what() + " when initializing "s + description};
} catch (...) {
    throw std::invalid_argument{"unknown exception when initializing "s + description};
}

memory_address_range::memory_address_range(const std::string &description, uint64_t start, uint64_t length,
    const pmas_flags &flags, const std::string &image_filename, const callocd & /*c*/) try :
    address_range(description.c_str(), start, length, flags, [](const char *err) { throw base_error{err}; }),
    m_ptr{make_unique_calloc<unsigned char>(length)},
    m_host_memory{std::get<callocd_ptr>(m_ptr).get()} {
    if (!is_memory()) {
        throw std::invalid_argument{"memory range must be flagged memory when initializing "s + description};
    }
    m_dirty_page_map.resize((length / (8 * AR_PAGE_SIZE)) + 1, 0xff);
    // Try to load image file, if any
    if (!image_filename.empty()) {
        auto fp = make_unique_fopen(image_filename.c_str(), "rb", std::nothrow_t{});
        if (!fp) {
            throw std::system_error{errno, std::generic_category(), "error opening image file '"s + image_filename};
        }
        // Get file size
        if (fseek(fp.get(), 0, SEEK_END) != 0) {
            throw std::system_error{errno, std::generic_category(),
                "error obtaining length of image file '"s + image_filename};
        }
        const auto file_length = static_cast<uint64_t>(ftello(fp.get()));
        if (fseek(fp.get(), 0, SEEK_SET) != 0) {
            throw std::system_error{errno, std::generic_category(),
                "error obtaining length of image file '"s + image_filename};
        }
        // Check against PMA range size
        if (file_length > length) {
            throw std::runtime_error{"image file '"s + image_filename + "' is too large for range"s};
        }
        // Read to host memory
        const auto read_length = static_cast<uint64_t>(fread(m_host_memory, 1, file_length, fp.get()));
        if (read_length != file_length) {
            throw std::runtime_error{"error reading from image file '"s + image_filename};
        }
    }
} catch (base_error &b) {
    throw; // already contains the description
} catch (std::exception &e) {
    throw std::invalid_argument{e.what() + " when initializing "s + description};
} catch (...) {
    throw std::invalid_argument{"unknown exception when initializing "s + description};
}

} // namespace cartesi
