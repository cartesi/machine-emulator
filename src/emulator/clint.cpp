#include "clint.h"
#include "machine.h"

static bool clint_read_msip(i_device_state_access *a, uint64_t *val, int size_log2) {
    if (size_log2 == 2) {
        *val = ((a->read_mip() & MIP_MSIP) == MIP_MSIP);
        return true;
    }
    return false;
}

static bool clint_read_mtime(i_device_state_access *a, uint64_t *val, int size_log2) {
    if (size_log2 == 3) {
        *val = processor_rtc_cycles_to_time(a->read_mcycle());
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

bool clint_read(i_device_state_access *a, void *context, uint64_t offset, uint64_t *val, int size_log2) {
    (void) context;

    switch (offset) {
        case 0: // Machine software interrupt for hart 0
            return clint_read_msip(a, val, size_log2);
        case 0xbff8: // mtime
            return clint_read_mtime(a, val, size_log2);
        case 0x4000: // mtimecmp
            return clint_read_mtimecmp(a, val, size_log2);
        default:
            // other reads are exceptions
            return false;
    }
}

bool clint_write(i_device_state_access *a, void *context, uint64_t offset, uint64_t val, int size_log2) {
    (void) context;

    switch (offset) {
        case 0: // Machine software interrupt for hart 0
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
        case 0x4000: // mtimecmp
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
