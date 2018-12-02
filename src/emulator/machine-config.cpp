#include <cstring>

#include "cartesi-constants.h"
#include "riscv-constants.h"
#include "machine-config.h"

namespace cartesi {

machine_config::machine_config(void):
    processor{},
    ram{},
    rom{},
    flash{},
    clint{},
    htif{},
    interactive{false} {
    // Starting address is 4k
    processor.pc = 0x1000;
    // M-mode
    processor.iflags = static_cast<uint64_t>(PRV_M) << IFLAGS_PRV_SHIFT;
    // No reservation
    processor.ilrsc = -1;
    // Set S and U XLEN in mstatus
    processor.mstatus = (MISA_MXL_VALUE << MSTATUS_UXL_SHIFT) |
        (MISA_MXL_VALUE << MSTATUS_SXL_SHIFT);
    // Set our extensions in misa
    processor.misa = MISA_MXL_VALUE << MISA_MXL_SHIFT;
    processor.misa |=
        MISA_EXT_S_MASK |
        MISA_EXT_U_MASK |
        MISA_EXT_I_MASK |
        MISA_EXT_M_MASK |
        MISA_EXT_A_MASK;
    // Set our ids
    processor.mvendorid = VENDORID;
    processor.marchid = ARCHID;
    processor.mimpid = IMPID;
}

} // namespace cartesi
