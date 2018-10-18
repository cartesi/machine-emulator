#include "clint.h"
#include "i-device-state-access.h"
#include "machine.h"
#include "machine-state.h"
#include "rtc.h"

#define CLINT_MSIP0    0
#define CLINT_MTIMECMP 0x4000
#define CLINT_MTIME    0xbff8

static bool clint_read_msip(i_device_state_access *a, uint64_t *val,
    int size_log2) {
    if (size_log2 == 2) {
        *val = ((a->read_mip() & MIP_MSIP) == MIP_MSIP);
        return true;
    }
    return false;
}

static bool clint_read_mtime(i_device_state_access *a, uint64_t *val, int size_log2) {
    if (size_log2 == 3) {
        *val = rtc_cycle_to_time(a->read_mcycle());
        return true;
    }
    return false;
}

static bool clint_read_mtimecmp(i_device_state_access *a, uint64_t *val, int size_log2) {
    if (size_log2 == 3) {
        *val = a->read_mtimecmp();
        return true;
    }
    return false;
}

/// \brief CLINT device read callback. See ::pma_device_read.
bool clint_read(i_device_state_access *a, void *context, uint64_t offset, uint64_t *val, int size_log2) {
    (void) context;

    switch (offset) {
        case CLINT_MSIP0:    // Machine software interrupt for hart 0
            return clint_read_msip(a, val, size_log2);
        case CLINT_MTIMECMP: // mtimecmp
            return clint_read_mtimecmp(a, val, size_log2);
        case CLINT_MTIME:    // mtime
            return clint_read_mtime(a, val, size_log2);
        default:
            // other reads are exceptions
            return false;
    }
}

/// \brief CLINT device read callback. See ::pma_device_write.
bool clint_write(i_device_state_access *a, void *context, uint64_t offset, uint64_t val, int size_log2) {
    (void) context;

    switch (offset) {
        case CLINT_MSIP0: // Machine software interrupt for hart 0
            if (size_log2 == 2) {
                //??D I don't yet know why Linux tries to raise MSIP when we only have a single hart
                //    It does so repeatedly before and after every command run in the shell
                //    Will investigate.
                if (val & 1) {
                    a->set_mip(MIP_MSIP);
                } else {
                    a->reset_mip(MIP_MSIP);
                }
                return true;
            }
            return false;
        case CLINT_MTIMECMP: // mtimecmp
            if (size_log2 == 3) {
                a->write_mtimecmp(val);
                a->reset_mip(MIP_MTIP);
                return true;
            }
            // partial mtimecmp is not supported
            return false;
        default:
            // other writes are exceptions
            return false;
    }
}

static bool clint_peek_msip(const machine_state *s, uint64_t *val, int size_log2) {
    if (size_log2 == 2) {
        *val = ((s->mip & MIP_MSIP) == MIP_MSIP);
        return true;
    }
    return false;
}

static bool clint_peek_mtime(const machine_state *s, uint64_t *val, int size_log2) {
    if (size_log2 == 3) {
        *val = rtc_cycle_to_time(s->mcycle);
        return true;
    }
    return false;
}

static bool clint_peek_mtimecmp(const machine_state *s, uint64_t *val, int size_log2) {
    if (size_log2 == 3) {
        *val = s->mtimecmp;
        return true;
    }
    return false;
}

/// \brief CLINT device peek callback. See ::pma_device_peek.
bool clint_peek(const machine_state *s, void *context, uint64_t offset, uint64_t *val, int size_log2) {
    (void) context;

    switch (offset) {
        case CLINT_MSIP0:    // Machine software interrupt for hart 0
            return clint_peek_msip(s, val, size_log2);
        case CLINT_MTIMECMP: // mtimecmp
            return clint_peek_mtimecmp(s, val, size_log2);
        case CLINT_MTIME: // mtime
            return clint_peek_mtime(s, val, size_log2);
        default:
            // other reads are exceptions
            return false;
    }
}

#define base(v) ((v) - ((v) % merkle_tree::get_page_size()))
#define offset(v) ((v) % merkle_tree::get_page_size())
/// \brief CLINT device update_merkle_tree callback. See ::pma_device_update_merkle_tree.
bool clint_update_merkle_tree(const machine_state *s, void *context, uint64_t start, uint64_t length,
    CryptoPP::Keccak_256 &kc, merkle_tree *t) {
    (void) context; (void) length;
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
        "code assumes little-endian byte ordering");
    auto page = reinterpret_cast<uint8_t *>(calloc(1, merkle_tree::get_page_size()));
    if (!page) return false;
    // There are 3 pages to be updated: 0, 4, and 11
    // Page 0 contains only msip (which is either 0 or 1)
    // Since we are little-endian, we can simply write the byte
    page[offset(CLINT_MSIP0)] = ((s->mip & MIP_MSIP) == MIP_MSIP);
    bool err = t->is_error(t->update_page(kc, start+base(CLINT_MSIP0), page));
    page[offset(CLINT_MSIP0)] = 0;
    // Page 4 contains only mtimecmp, which is an uint64_t
    *reinterpret_cast<uint64_t *>(page+offset(CLINT_MTIMECMP)) = s->mtimecmp;
    err |= t->is_error(t->update_page(kc, start+base(CLINT_MTIMECMP), page));
    *reinterpret_cast<uint64_t *>(page+offset(CLINT_MTIMECMP)) = 0;
    // The third page contains only mtime, which is an uint64_t
    *reinterpret_cast<uint64_t *>(page+offset(CLINT_MTIME)) = rtc_cycle_to_time(s->mcycle);
    err |= t->is_error(t->update_page(kc, start+base(CLINT_MTIME), page));
    *reinterpret_cast<uint64_t *>(page+offset(CLINT_MTIME)) = 0;
    free(page);
    return !err;
}
#undef base
#undef offset

pma_device_driver clint_driver = {
    clint_read,
    clint_write,
    clint_peek,
    clint_update_merkle_tree
};
