#ifndef CARTESI_CONSTANTS
#define CARTESI_CONSTANTS

/// \file
/// \brief Cartesi-specific constants

/// \name Cartesi-machine ids
/// \{
#define VENDORID UINT64_C(0x6361727465736920) ///< Value of mvendorid
#define ARCHID UINT64_C(1) ///< Value of marchid
#define IMPID UINT64_C(1) ///< Value of mimpid
/// \}

/// \name Cartesi-specific iflags shifts
/// \{
#define IFLAGS_H_SHIFT   0
#define IFLAGS_I_SHIFT   1
#define IFLAGS_PRV_SHIFT 2
/// \}

#endif
