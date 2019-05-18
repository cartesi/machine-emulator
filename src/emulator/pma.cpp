#include <sys/mman.h> // mmap, munmap
#include <unistd.h> // close
#include <sys/stat.h> // fstat
#include <fcntl.h> // open
#include <errno.h>

#include <string>
#include <system_error>

#include "unique-c-ptr.h"
#include "pma.h"

namespace cartesi {

using namespace std::string_literals;

pma_memory::~pma_memory() {
    if (m_backing_file >= 0) {
        munmap(m_host_memory, m_length);
        close(m_backing_file);
    } else {
        free(m_host_memory);
    }
}

pma_memory::pma_memory(pma_memory &&other):
    m_length{std::move(other.m_length)},
    m_host_memory{std::move(other.m_host_memory)},
    m_backing_file{std::move(other.m_backing_file)},
    m_dirty_page_map{std::move(other.m_dirty_page_map)} {
    other.m_host_memory = nullptr;
    other.m_backing_file = -1;
    other.m_length = 0;
}

pma_memory::pma_memory(uint64_t length, const callocd &c):
    m_length{length},
    m_host_memory{nullptr},
    m_backing_file{-1} {
    (void) c;
    m_host_memory = reinterpret_cast<uint8_t *>(calloc(1, length));
    if (!m_host_memory)
        throw std::bad_alloc{};
    // allocate dirty page map and mark all as dirty
    m_dirty_page_map.resize(length/(8*PMA_PAGE_SIZE)+1, 0xff);
}

pma_memory::pma_memory(uint64_t length, const std::string &path,
    const callocd &c):
    pma_memory{length, c} {
    // Try to load backing file, if any
    if (!path.empty()) {
        auto fp = unique_fopen(path.c_str(), "rb", std::nothrow_t{});
        if (!fp) {
            throw std::system_error{errno, std::generic_category(),
                "error opening backing file '"s + path + "'"s};
        }
        auto read = fread(m_host_memory, 1, length, fp.get()); (void) read;
        if (ferror(fp.get())) {
            throw std::system_error{errno, std::generic_category(),
                "error reading from backing file '"s + path + "'"s};
        }
        if (!feof(fp.get())) {
            throw std::runtime_error{
                "backing file '" + path + "' too large for range"};
        }
    }
}

pma_memory::pma_memory(uint64_t length, const std::string &path,
    const mmapd &m):
    m_length{length},
    m_host_memory{nullptr},
    m_backing_file{-1} {
    if (path.empty())
        throw std::runtime_error{"backing file required"};

    int oflag = m.shared? O_RDWR: O_RDONLY;
    int mflag = m.shared? MAP_SHARED: MAP_PRIVATE;

    // Try to open backing file
    int backing_file = open(path.c_str(), oflag);
    if (backing_file < 0)
        throw std::system_error{errno, std::generic_category(),
            "could not open backing file '"s + path + "'"s};

    // Try to get file size
    struct stat statbuf;
    if (fstat(backing_file, &statbuf) < 0) {
        close(backing_file);
        throw std::system_error{errno, std::generic_category(),
            "unable to stat backing file '"s + path + "'"s};
    }

    // Check that it matches range length
    if (static_cast<uint64_t>(statbuf.st_size) != length) {
        close(backing_file);
        throw std::invalid_argument{"backing file size does not match range length"};
    }

    // Try to map backing file to host memory
    uint8_t *host_memory = reinterpret_cast<uint8_t *>(
        mmap(nullptr, length, PROT_READ | PROT_WRITE, mflag, backing_file, 0));
    if (host_memory == MAP_FAILED) {
        close(backing_file);
        throw std::system_error{errno, std::generic_category(),
            "could not map backing file '"s + path + "' to memory"s};
    }

    // Finally store everything in object
    m_host_memory = host_memory;
    m_backing_file = backing_file;
    // allocate dirty page map and mark all as dirty
    m_dirty_page_map.resize(length/(8*PMA_PAGE_SIZE)+1, 0xff);
}

pma_memory& pma_memory::operator=(pma_memory &&other) {
    m_host_memory = std::move(other.m_host_memory);
    m_backing_file = std::move(other.m_backing_file);
    m_length = std::move(other.m_length);
    m_dirty_page_map = std::move(other.m_dirty_page_map);
    other.m_host_memory = nullptr;
    other.m_backing_file = -1;
    other.m_length = 0;
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

/// \brief Default device write callback issues error on write.
bool pma_write_error(const pma_entry &, i_virtual_state_access *, uint64_t, uint64_t, int) {
    return false;
}

/// \brief Default device read callback issues error on reads.
bool pma_read_error(const pma_entry &, i_virtual_state_access *, uint64_t, uint64_t *, int) {
    return false;
}

/// \brief Default device peek callback issues error on peeks.
bool pma_peek_error(const pma_entry &, uint64_t, const uint8_t **, uint8_t *) {
    return false;
}

} // namespace cartesi
