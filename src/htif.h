// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef HTIF_H
#define HTIF_H

#include "pma-driver.h"
#include <array>
#include <cstdint>
#include <htif-defines.h>
#include <pma-defines.h>

/// \file
/// \brief Host-Target interface device.

namespace cartesi {

/// \brief Global HTIF device driver instance
extern const pma_driver htif_driver;

// Forward declarations
/// \brief HTIF shifts
enum HTIF_shifts {
    HTIF_DEV_SHIFT = HTIF_DEV_SHIFT_DEF,
    HTIF_CMD_SHIFT = HTIF_CMD_SHIFT_DEF,
    HTIF_DATA_SHIFT = HTIF_DATA_SHIFT_DEF
};

/// \brief HTIF shifts
enum HTIF_masks : uint64_t {
    HTIF_DEV_MASK = EXPAND_UINT64_C(HTIF_DEV_MASK_DEF),
    HTIF_CMD_MASK = EXPAND_UINT64_C(HTIF_CMD_MASK_DEF),
    HTIF_DATA_MASK = EXPAND_UINT64_C(HTIF_DATA_MASK_DEF)
};

static constexpr uint64_t HTIF_BUILD(uint64_t dev, uint64_t cmd, uint64_t data) {
    return ((dev << HTIF_DEV_SHIFT) & HTIF_DEV_MASK) | ((cmd << HTIF_CMD_SHIFT) & HTIF_CMD_MASK) |
        ((data << HTIF_DATA_SHIFT) & HTIF_DATA_MASK);
}

static constexpr uint64_t HTIF_DEV_FIELD(uint64_t reg) {
    return (reg & HTIF_DEV_MASK) >> HTIF_DEV_SHIFT;
}

static constexpr uint64_t HTIF_CMD_FIELD(uint64_t reg) {
    return (reg & HTIF_CMD_MASK) >> HTIF_CMD_SHIFT;
}

static constexpr uint64_t HTIF_DATA_FIELD(uint64_t reg) {
    return (reg & HTIF_DATA_MASK) >> HTIF_DATA_SHIFT;
}

static constexpr uint64_t HTIF_REPLACE_DATA(uint64_t reg, uint64_t data) {
    return (reg & (~HTIF_DATA_MASK)) | ((data << HTIF_DATA_SHIFT) & HTIF_DATA_MASK);
}

/// \brief HTIF devices
enum HTIF_devices : uint64_t {
    HTIF_DEVICE_HALT = HTIF_DEVICE_HALT_DEF,       ///< Used to halt machine
    HTIF_DEVICE_CONSOLE = HTIF_DEVICE_CONSOLE_DEF, ///< Used for console input and output
    HTIF_DEVICE_YIELD = HTIF_DEVICE_YIELD_DEF,     ///< Used to yield control back to host
};

/// \brief HTIF commands
enum HTIF_commands : uint64_t {
    HTIF_HALT_HALT = HTIF_HALT_HALT_DEF,
    HTIF_CONSOLE_GETCHAR = HTIF_CONSOLE_GETCHAR_DEF,
    HTIF_CONSOLE_PUTCHAR = HTIF_CONSOLE_PUTCHAR_DEF,
    HTIF_YIELD_MANUAL = HTIF_YIELD_MANUAL_DEF,
    HTIF_YIELD_AUTOMATIC = HTIF_YIELD_AUTOMATIC_DEF,
};

/// \brief HTIF yield reasons
enum HTIF_yield_reason : uint64_t {
    HTIF_YIELD_REASON_PROGRESS = HTIF_YIELD_REASON_PROGRESS_DEF,
    HTIF_YIELD_REASON_RX_ACCEPTED = HTIF_YIELD_REASON_RX_ACCEPTED_DEF,
    HTIF_YIELD_REASON_RX_REJECTED = HTIF_YIELD_REASON_RX_REJECTED_DEF,
    HTIF_YIELD_REASON_TX_VOUCHER = HTIF_YIELD_REASON_TX_VOUCHER_DEF,
    HTIF_YIELD_REASON_TX_NOTICE = HTIF_YIELD_REASON_TX_NOTICE_DEF,
    HTIF_YIELD_REASON_TX_REPORT = HTIF_YIELD_REASON_TX_REPORT_DEF,
    HTIF_YIELD_REASON_TX_EXCEPTION = HTIF_YIELD_REASON_TX_EXCEPTION_DEF,
};
/// \brief Mapping between CSRs and their relative addresses in HTIF memory
enum class htif_csr {
    tohost = UINT64_C(0x0),
    fromhost = UINT64_C(0x8),
    ihalt = UINT64_C(0x10),
    iconsole = UINT64_C(0x18),
    iyield = UINT64_C(0x20)
};

} // namespace cartesi

#endif
