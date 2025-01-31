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

#ifndef RTC_H
#define RTC_H

#include <cstdint>

#include "rtc-defines.h"

/// \file
/// \brief Real Time Clock

namespace cartesi {

/// \brief RTC constants
enum RTC_constants : uint64_t {
    RTC_FREQ_DIV = RTC_FREQ_DIV_DEF,                             ///< Clock divisor is set stone in whitepaper
    RTC_CLOCK_FREQ = RTC_CLOCK_FREQ_DEF,                         ///< Clock frequency
    RTC_US_PER_TICK = (1000000 * RTC_FREQ_DIV) / RTC_CLOCK_FREQ, /// < Microsecond per clock tick
};

/// \brief Returns whether the cycle is a RTC tick
/// \param cycle Cycle count
static inline bool rtc_is_tick(uint64_t cycle) {
    return (cycle % RTC_FREQ_DIV) == 0;
}

} // namespace cartesi

#endif
