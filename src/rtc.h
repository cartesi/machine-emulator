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

#ifndef RTC_H
#define RTC_H

#include <cstdint>

#include <rtc-defines.h>

/// \file
/// \brief Real Time Clock

namespace cartesi {

/// \brief RTC constants
enum RTC_constants {
    RTC_FREQ_DIV  = RTC_FREQ_DIV_DEF ///< Clock divisor is set stone in whitepaper
};

/// \brief Converts from cycle count to time count
/// \param cycle Cycle count
/// \returns Time count
static inline uint64_t rtc_cycle_to_time(uint64_t cycle) {
    return cycle / RTC_FREQ_DIV;
}

/// \brief Converts from time count to cycle count
/// \param time Time count
/// \returns Cycle count
static inline uint64_t rtc_time_to_cycle(uint64_t time) {
    return time * RTC_FREQ_DIV;
}

/// \brief Returns whether the cycle is a RTC tick
/// \param cycle Cycle count
static inline bool rtc_is_tick(uint64_t cycle) {
    return (cycle % RTC_FREQ_DIV) == 0;
}

} // namespace cartesi

#endif
