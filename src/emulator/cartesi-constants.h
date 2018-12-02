#ifndef CARTESI_CONSTANTS
#define CARTESI_CONSTANTS

#include <cstdint>

/// \file
/// \brief Cartesi-specific constants

namespace cartesi {

/// \brief Cartesi-machine ids
enum IDs: uint64_t {
    VENDORID = UINT64_C(0x6361727465736920), ///< Value for mvendorid
    ARCHID   = UINT64_C(1), ///< Value for marchid
    IMPID    = UINT64_C(1), ///< Value for mimpid
};

/// \brief Cartesi-specific iflags shifts
enum IFLAGS_shifts {
    IFLAGS_H_SHIFT  = 0,
    IFLAGS_I_SHIFT  = 1,
    IFLAGS_PRV_SHIFT= 2
};

} // namespace cartesi

#endif
