#ifndef PMA_CONSTANTS_H
#define PMA_CONSTANTS_H

#include <cstdint>

#include "pma-defines.h"

namespace cartesi {

/// \file
/// \brief Physical memory attributes constants.

/// \brief Fixed PMA ranges.
enum PMA_ranges: uint64_t {
    PMA_SHADOW_START  = UINT64_C(0),           ///< Start of shadow range
    PMA_SHADOW_LENGTH = UINT64_C(0x1000),      ///< Length of shadow range
    PMA_ROM_START     = EXPAND_UINT64_C(PMA_ROM_START_DEF), ///< Start of ROM range
    PMA_ROM_LENGTH    = EXPAND_UINT64_C(PMA_ROM_LENGTH_DEF),  ///< Length of ROM range
    PMA_CLINT_START   = UINT64_C(0x2000000),   ///< Start of CLINT range
    PMA_CLINT_LENGTH  = UINT64_C(0xC0000),     ///< Length of CLINT range
    PMA_HTIF_START    = EXPAND_UINT64_C(PMA_HTIF_START_DEF),///< Start of HTIF range
    PMA_HTIF_LENGTH   = UINT64_C(0x1000),      ///< Length of HTIF range
    PMA_RAM_START     = EXPAND_UINT64_C(PMA_RAM_START_DEF),  ///< Start of RAM range
};

/// \brief PMA constants.
enum PMA_constants: uint64_t {
    PMA_PAGE_SIZE_LOG2 = 12, ///< log<sub>2</sub> of physical memory page size.
    PMA_PAGE_SIZE      = (UINT64_C(1) << PMA_PAGE_SIZE_LOG2), ///< Physical memory page size.
    PMA_WORD_SIZE      = UINT64_C(8), ///< Physical memory word size.
    PMA_MAX            = UINT64_C(32), ///< Maximum number of PMAs
    PMA_BOARD_SHADOW_START = EXPAND_UINT64_C(PMA_START_DEF) ///< Base of board shadow, where PMAs start
};

/// \brief PMA istart shifts
enum PMA_ISTART_shifts {
    PMA_ISTART_M_SHIFT  = 0,
    PMA_ISTART_IO_SHIFT = 1,
    PMA_ISTART_E_SHIFT  = 2,
    PMA_ISTART_R_SHIFT  = 3,
    PMA_ISTART_W_SHIFT  = 4,
    PMA_ISTART_X_SHIFT  = 5,
    PMA_ISTART_IR_SHIFT = 6,
    PMA_ISTART_IW_SHIFT = 7,
    PMA_ISTART_DID_SHIFT = 8,
};

/// \brief PMA istart masks
enum PMA_ISTART_masks: uint64_t {
    PMA_ISTART_M_MASK   = UINT64_C(1)  << PMA_ISTART_M_SHIFT,  ///< Memory range
    PMA_ISTART_IO_MASK  = UINT64_C(1)  << PMA_ISTART_IO_SHIFT, ///< Device range
    PMA_ISTART_E_MASK   = UINT64_C(1)  << PMA_ISTART_E_SHIFT,  ///< Empty range
    PMA_ISTART_R_MASK   = UINT64_C(1)  << PMA_ISTART_R_SHIFT,  ///< Readable
    PMA_ISTART_W_MASK   = UINT64_C(1)  << PMA_ISTART_W_SHIFT,  ///< Writable
    PMA_ISTART_X_MASK   = UINT64_C(1)  << PMA_ISTART_X_SHIFT,  ///< Executable
    PMA_ISTART_IR_MASK  = UINT64_C(1)  << PMA_ISTART_IR_SHIFT, ///< Idempotent reads
    PMA_ISTART_IW_MASK  = UINT64_C(1)  << PMA_ISTART_IW_SHIFT, ///< Idempotent writes
    PMA_ISTART_DID_MASK = UINT64_C(15) << PMA_ISTART_DID_SHIFT ///< Device id
};

/// \brief PMA device ids
enum class PMA_ISTART_DID {
    memory = 0, ///< DID for memory
    shadow = 1, ///< DID for shadow device
    drive  = 2, ///< DID for drive device
    CLINT  = 3, ///< DID for CLINT device
    HTIF   = 4  ///< DID for HTIF device
};

} // namespace

#endif
