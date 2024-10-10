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

#include "pma.h"

#include <cerrno>
#include <cstring>
#include <string>
#include <system_error>

#include "machine-config.h"
#include "os.h"
#include "unique-c-ptr.h"

namespace cartesi {

using namespace std::string_literals;

void pma_memory::release(void) {
    os_munmap(m_mmaped);
    m_mmaped = os_mmapd{};
}

pma_memory::~pma_memory() {
    release();
}

pma_memory::pma_memory(pma_memory &&other) noexcept : m_mmaped{std::move(other.m_mmaped)} {
    // set other to safe state
    other.m_mmaped = os_mmapd{};
}

pma_memory::pma_memory(const std::string &description, uint64_t length, const std::string &path, bool shared) {
    try {
        int flags = 0;
        if (shared) {
            flags |= OS_MMAP_SHARED;
        }
        if (!path.empty()) {
            flags |= OS_MMAP_LOCKBACKING;
        }
        m_mmaped = os_mmap(length, flags, path);
    } catch (std::exception &e) {
        throw std::runtime_error{e.what() + " when initializing "s + description};
    }
}

pma_memory &pma_memory::operator=(pma_memory &&other) noexcept {
    release();
    // copy from other
    m_mmaped = std::move(other.m_mmaped);
    // set other to safe state
    other.m_mmaped = os_mmapd{};
    return *this;
}

uint64_t pma_entry::get_istart(void) const {
    uint64_t istart = m_start;
    istart |= (static_cast<uint64_t>(get_istart_M()) << PMA_ISTART_M_SHIFT);
    istart |= (static_cast<uint64_t>(get_istart_IO()) << PMA_ISTART_IO_SHIFT);
    istart |= (static_cast<uint64_t>(get_istart_E()) << PMA_ISTART_E_SHIFT);
    istart |= (static_cast<uint64_t>(get_istart_R()) << PMA_ISTART_R_SHIFT);
    istart |= (static_cast<uint64_t>(get_istart_W()) << PMA_ISTART_W_SHIFT);
    istart |= (static_cast<uint64_t>(get_istart_X()) << PMA_ISTART_X_SHIFT);
    istart |= (static_cast<uint64_t>(get_istart_IR()) << PMA_ISTART_IR_SHIFT);
    istart |= (static_cast<uint64_t>(get_istart_IW()) << PMA_ISTART_IW_SHIFT);
    istart |= (static_cast<uint64_t>(get_istart_DID()) << PMA_ISTART_DID_SHIFT);
    return istart;
}

uint64_t pma_entry::get_ilength(void) const {
    return m_length;
}

void pma_entry::write_memory(uint64_t paddr, const unsigned char *data, uint64_t size) {
    if (!get_istart_M() || get_istart_E()) {
        throw std::invalid_argument{"address range not entirely in memory PMA"};
    }
    if (!contains(paddr, size)) {
        throw std::invalid_argument{"range not contained in pma"};
    }
    if (!data) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    memcpy(get_memory().get_host_memory() + (paddr - get_start()), data, size);
    mark_dirty_pages(paddr, size);
}

void pma_entry::fill_memory(uint64_t paddr, unsigned char value, uint64_t size) {
    if (!get_istart_M() || get_istart_E()) {
        throw std::invalid_argument{"address range not entirely in memory PMA"};
    }
    if (!contains(paddr, size)) {
        throw std::invalid_argument{"range not contained in pma"};
    }
    memset(get_memory().get_host_memory() + (paddr - get_start()), value, size);
    mark_dirty_pages(paddr, size);
}

bool pma_peek_error(const pma_entry &, const machine &, uint64_t, const unsigned char **, unsigned char *) {
    return false;
}

/// \brief Memory range peek callback. See pma_peek.
static bool memory_peek(const pma_entry &pma, const machine &m, uint64_t page_address, const unsigned char **page_data,
    unsigned char *scratch) {
    // TODO(edubart): use pread to avoid faulting page
    (void) m;
    // If page_address is not aligned, or if it is out of range, return error
    if ((page_address & (PMA_PAGE_SIZE - 1)) != 0 || page_address > pma.get_length()) {
        *page_data = nullptr;
        return false;
    }
    // If page is only partially inside range, copy to scratch
    if (page_address + PMA_PAGE_SIZE > pma.get_length()) {
        memset(scratch, 0, PMA_PAGE_SIZE);
        memcpy(scratch, pma.get_memory().get_host_memory() + page_address, pma.get_length() - page_address);
        *page_data = scratch;
        return true;
        // Otherwise, return pointer directly into host memory
    } else {
        *page_data = pma.get_memory().get_host_memory() + page_address;
        return true;
    }
}

pma_entry make_mmapd_memory_pma_entry(const std::string &description, uint64_t start, uint64_t length,
    const std::string &path, bool shared) {
    if (length == 0) {
        throw std::invalid_argument{description + " length cannot be zero"s};
    }
    return pma_entry{description, start, length, pma_memory{description, length, path, shared}, memory_peek};
}

pma_entry make_memory_range_pma_entry(const std::string &description, pma_entry::flags flags, uint64_t start,
    uint64_t length, const std::string &image_filename, bool shared, const machine_runtime_config &r) {
    std::string backing_filename = image_filename;
    if (!r.backing_storage.empty()) {
        backing_filename = machine_config::get_image_filename(r.backing_storage, start, length);
        if (!image_filename.empty()) {
            if (shared && backing_filename != image_filename) {
                throw std::runtime_error(
                    "PMA "s + description + " cannot be shared simultaneously with backing storage runtime option"s);
            }
            if (backing_filename != image_filename) {
                if (r.copy_reflink) {
                    os_copy_reflink(image_filename.c_str(), backing_filename.c_str());
                } else {
                    os_copy_file(image_filename.c_str(), backing_filename.c_str());
                }
                os_grow_file(backing_filename.c_str(), length, false);
            }
        } else {
            os_grow_file(backing_filename.c_str(), length, true);
        }
        shared = true;
    }
    return make_mmapd_memory_pma_entry(description, start, length, backing_filename, shared).set_flags(flags);
}

pma_entry make_device_pma_entry(const std::string &description, uint64_t start, uint64_t length, pma_peek peek,
    const pma_driver *driver, void *context) {
    if (length == 0) {
        throw std::invalid_argument{description + " length cannot be zero"s};
    }
    return pma_entry{description, start, length, pma_device{description, driver, context}, peek};
}

pma_entry make_empty_pma_entry(const std::string &description, uint64_t start, uint64_t length) {
    return pma_entry{description, start, length};
}

} // namespace cartesi
